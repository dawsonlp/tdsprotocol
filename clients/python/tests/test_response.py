"""Tests of the response's record and reading rules (D-34, D-42) against the core alone.

Responses captured from the live server (response_samples.py) are fed to the state machine whole and in pieces. The
tests use no server and no network.
"""

import asyncio
import gc
import random
from dataclasses import replace

import pytest

import response_samples as samples
from tds.response import (Cancelled, CompletionKind, Error, FetchedResponse, Message, NotYetRead, Response,
                          ResponseReader, ResultSet, RowsNotAvailable, ServerError, Unread)
from tds.tokens import DoneStatus, EnvKind
from tds.wire import MalformedMessage

ACK = bytes.fromhex("FD 20 00 00 00 00 00 00 00 00 00 00 00")  # DONE · acknowledges a cancel · final
NAMES = ["TWO_RESULT_SETS", "COUNTS", "NOCOUNT", "STATEMENT_FAILS", "BATCH_ENDS", "EXEC_IN_BATCH", "ORDERED",
         "NULL_BITMAP", "MESSAGES", "ASSIGNMENTS", "DIVIDE_BY_ZERO_DEFAULTS", "USE_DATABASE", "TWO_CALLS",
         "REFUSED_THEN_RUNS", "CALL_ENDS_REQUEST"]


def reader(body: bytes, pieces: list[int] | None = None, keep: bool = True) -> ResponseReader:
    """Feed a whole response, cut at the given sizes (one packet by default)."""
    r = ResponseReader(record=True, announce=lambda change: None)
    r.keep_new = keep
    cuts, at = [], 0
    for size in pieces or [len(body)]:
        if at >= len(body):
            break
        cuts.append(body[at : at + size])
        at += size
    if at < len(body):
        cuts.append(body[at:])
    for i, chunk in enumerate(cuts):
        r.feed(chunk, last=i == len(cuts) - 1)
    return r


def outline(r: ResponseReader) -> list:
    """The record, as plain values to compare."""
    out = []
    for item in r.sequence:
        if isinstance(item, ResultSet):
            out.append(("set", [c.name for c in item.columns], item.order, item.rows, item.completion))
        else:
            out.append(item)
    return out


def at_server(record: list, server_name: str) -> list:
    """Bind a captured record's named reports to the live server, leaving every other field unchanged.

    Only expected records pass through this helper. Actual reports must still name the server queried on the
    connection. Empty server fields stay empty; rows and message text are never rewritten.
    """
    assert server_name, "the live connection must report its server name"
    expected = []
    for item in record:
        if isinstance(item, (Error, Message)) and item.server:
            assert item.server == samples.SERVER_NAME, "record the sample's server provenance before rebinding it"
            item = replace(item, server=server_name)
        expected.append(item)
    return expected


@pytest.mark.parametrize("server_name", ["new-container", "sql-host\\INSTANCE"])
def test_binding_a_capture_changes_only_the_reports_server(server_name):
    error = next(item for item in reader(samples.REFUSED_THEN_RUNS).sequence if isinstance(item, Error))
    message = next(item for item in reader(samples.MESSAGES).sequence if isinstance(item, Message))
    message = replace(message, text=samples.SERVER_NAME)
    unnamed = replace(error, server="")
    row = ("set", ["server"], (), ((samples.SERVER_NAME,),), None)
    original = [error, message, unnamed, row]

    assert at_server(original, server_name) == [replace(error, server=server_name),
                                               replace(message, server=server_name), unnamed, row]
    assert original == [error, message, unnamed, row] and error.server == samples.SERVER_NAME


def test_binding_refuses_an_unrecorded_capture_origin():
    error = next(item for item in reader(samples.REFUSED_THEN_RUNS).sequence if isinstance(item, Error))
    with pytest.raises(AssertionError, match="provenance"):
        at_server([replace(error, server="unrecorded-origin")], "live-server")


def counts(r: ResponseReader) -> list:
    return [c.rows for c in r.completions]


def codes(r: ResponseReader) -> list:
    return [c.statement for c in r.completions]


# --------------------------------------------------------------------------- the record is the same for any packet size


@pytest.mark.parametrize("name", NAMES)
def test_the_record_is_the_same_however_the_bytes_are_cut(name):
    body = getattr(samples, name)
    whole = outline(reader(body))
    assert outline(reader(body, [1] * len(body))) == whole  # one byte per packet
    rng = random.Random(name)
    for _ in range(20):
        sizes = [rng.randint(1, 40) for _ in range(len(body))]
        assert outline(reader(body, sizes)) == whole


@pytest.mark.parametrize("name", NAMES)
def test_the_record_is_the_same_at_every_observability_level(name):
    body = getattr(samples, name)
    quiet = ResponseReader(record=False, announce=lambda change: None)
    quiet.keep_new = True
    quiet.feed(body, last=True)
    assert outline(quiet) == outline(reader(body))


# --------------------------------------------------------------------------- what the server sent (Request Response)


def test_each_result_set_has_columns_then_rows_then_its_completion():
    r = reader(samples.TWO_RESULT_SETS)
    first, second = r.result_sets
    assert [c.name for c in first.columns] == ["a"] and first.rows == ((1,), (2,))
    assert first.completion.rows == 2
    assert [c.name for c in second.columns] == ["b"] and second.rows == ()  # an empty result set still has columns…
    assert second.completion.rows == 0  # …and a count of 0


def test_counts_with_and_without_a_result_set():
    r = reader(samples.COUNTS)
    assert counts(r) == [3, 2, 3, 3]  # INSERT, UPDATE, SELECT, DELETE. DECLARE sends nothing.
    assert codes(r) == [195, 197, 193, 196]
    [selected] = r.result_sets
    assert selected.rows == ((1,), (3,), (4,)) and selected.completion is r.completions[2]


def test_nocount_withholds_the_count_not_the_completion():
    r = reader(samples.NOCOUNT)
    assert counts(r) == [None, None, None, None]  # a missing count is not 0
    assert all(DoneStatus.COUNT not in c.status for c in r.completions)
    assert codes(r) == [185, 195, 193, 186]  # SET … ON, INSERT, SELECT, SET … OFF


def test_a_failed_statement_lets_the_batch_go_on():
    r = reader(samples.STATEMENT_FAILS)
    assert [e.number for e in r.errors] == [8134]
    a, b, c = r.result_sets
    assert b.rows == () and DoneStatus.ERROR in b.completion.status and b.completion.rows is None
    assert c.rows == ((2,),)


def test_a_batch_ending_error_ends_the_response():
    r = reader(samples.BATCH_ENDS)
    assert [e.number for e in r.errors] == [245]
    assert len(r.result_sets) == 2  # SELECT 2 never ran
    last = r.completions[-1]
    assert DoneStatus.ERROR in last.status and DoneStatus.MORE not in last.status and r.ended


def test_a_procedure_in_a_batch_ends_with_a_call_completion_and_a_return():
    r = reader(samples.EXEC_IN_BATCH)
    kinds = [c.kind for c in r.completions]
    assert kinds == [CompletionKind.STATEMENT_IN_PROCEDURE] * 3 + [CompletionKind.CALL, CompletionKind.STATEMENT]
    [returned] = r.returns
    assert returned.status == 5 and not returned.failed and len(returned.outputs) == 0


def test_order_and_null_bitmap_rows():
    ordered = reader(samples.ORDERED).result_sets[0]
    assert ordered.order == (1,) and ordered.rows == (("a", 1), ("b", 2))
    [row] = reader(samples.NULL_BITMAP).result_sets[0].rows
    assert row == (None,) * 8 + (42,)


def test_messages_sit_where_they_happened_with_the_severity_reported():
    r = reader(samples.MESSAGES)
    assert [(m.number, m.severity, m.text) for m in r.messages] == [(0, 0, "hello"), (50000, 0, "just so you know")]
    assert codes(r) == [247, 246, 193]  # PRINT, RAISERROR, SELECT
    assert [type(i).__name__ for i in r.sequence] == ["Message", "Completion", "Message", "Completion", "ResultSet",
                                                       "Completion"]


def test_assignments_count_one_row():
    assert counts(reader(samples.ASSIGNMENTS)) == [1, 1, 1]


def test_division_by_zero_is_a_message_under_our_session_defaults():
    r = reader(samples.DIVIDE_BY_ZERO_DEFAULTS)
    assert [m.number for m in r.messages] == [3607] and r.errors == [] and r.result_sets[0].rows == ((None,),)


def test_announcements_are_recorded_and_passed_to_the_session():
    seen = []
    r = ResponseReader(record=False, announce=seen.append)
    r.feed(samples.USE_DATABASE, last=True)
    changes = [(i.kind, i.old, i.new) for i in r.sequence if type(i).__name__ == "Announcement"]
    assert [c for c in changes if c[0] == EnvKind.DATABASE] == [(EnvKind.DATABASE, "master", "tempdb"),
                                                               (EnvKind.DATABASE, "tempdb", "master")]
    assert {c[0] for c in changes} == {EnvKind.DATABASE, EnvKind.COLLATION}  # USE also announces the collation
    assert len(seen) == len(changes)


def test_calls_return_status_and_outputs_by_ordinal_and_name():
    r = reader(samples.TWO_CALLS)
    bump, outer = r.returns
    assert bump.status == 7 and bump.outputs[0].value == 42 and bump.outputs["@a"].ordinal == 0
    assert outer.status == 3 and outer.outputs["@o"].value == 101
    nested = [c for c in r.completions if c.statement == 224 and c.kind is CompletionKind.STATEMENT_IN_PROCEDURE]
    assert len(nested) == 1 and nested[0].rows is None  # the nested EXEC has no status and no outputs of its own


def test_a_refused_call_has_an_entry_and_the_next_call_runs():
    refused, bump = reader(samples.REFUSED_THEN_RUNS).returns
    assert refused.failed and refused.status is None and len(refused.outputs) == 0
    assert bump.status == 7 and bump.outputs["@a"].value == 6


def test_a_batch_ending_error_in_a_call_leaves_later_calls_without_entries():
    r = reader(samples.CALL_ENDS_REQUEST)
    [only] = r.returns  # two calls were sent
    assert only.failed and only.status is None and [e.number for e in r.errors] == [245] and r.ended


# --------------------------------------------------------------------------- malformed streams


def test_a_message_that_ends_without_a_final_done_is_malformed():
    with pytest.raises(MalformedMessage):
        reader(samples.COUNTS[:-13])  # the last DONE removed


def test_bytes_after_the_final_done_are_malformed():
    with pytest.raises(MalformedMessage):
        reader(samples.COUNTS + samples.COUNTS[-13:])


# --------------------------------------------------------------------------- reading a response (The Client §4)


class Feed:
    """A Source that feeds a captured response in packets of `size` bytes.

    A cancel adds the server's acknowledgement as a separate message, after the rest of the response.
    """

    def __init__(self, body: bytes, size: int = 16):
        self.chunks = [body[i : i + size] for i in range(0, len(body), size)]
        self.after: list[bytes] = []
        self.reader: ResponseReader | None = None
        self.pulls = 0

    async def read_more(self) -> None:
        self.pulls += 1
        if self.chunks:
            chunk = self.chunks.pop(0)
            self.reader.feed(chunk, last=not self.chunks)
        else:
            self.reader.feed(self.after.pop(0), last=True)

    def cancel(self) -> None:
        self.reader.cancelling = True
        self.after.append(ACK)

    def resume(self) -> None:
        self.reader.resume()

    def describe(self) -> str:
        return "a test feed"


def live(body: bytes, size: int = 16) -> tuple[Response, Feed]:
    source = Feed(body, size)
    source.reader = ResponseReader(record=False, announce=lambda change: None)
    return Response(source.reader, source), source


def run(coroutine):
    return asyncio.run(coroutine)


async def read_all(response) -> list:
    """Code written for a response. It works on live and fetched responses alike."""
    return [[row async for row in result_set] async for result_set in response]


def test_iterating_gives_result_sets_then_their_rows():
    response, _ = live(samples.TWO_RESULT_SETS)
    assert run(read_all(response)) == [[(1,), (2,)], []]
    assert response.ended and [c.rows for c in response.completions] == [2, 0]


def test_moving_on_discards_the_current_sets_unread_rows():
    async def go():
        response, _ = live(samples.COUNTS + b"", 8)
        sets = [rs async for rs in response]  # rows never read
        return sets

    [selected] = run(go())
    assert selected.rows_read == 3  # counted while they were skipped…
    with pytest.raises(RowsNotAvailable):
        selected.rows  # …but not kept


def test_a_passed_result_set_cant_be_read_again():
    async def go():
        response, _ = live(samples.TWO_RESULT_SETS)
        it = aiter(response)
        first = await anext(it)
        await anext(it)  # go to the next result set
        return [row async for row in first]

    with pytest.raises(RowsNotAvailable):
        run(go())


def test_fetch_returns_a_response_backed_by_memory_that_reads_the_same_and_indexes():
    async def go():
        response, _ = live(samples.TWO_RESULT_SETS)
        fetched = await response.fetch()
        return response, fetched, await read_all(fetched), await read_all(fetched)

    response, fetched, once, twice = run(go())
    assert isinstance(fetched, FetchedResponse) and response.ended
    assert once == twice == [[(1,), (2,)], []]  # read again
    assert fetched.result_sets[0].rows[1] == (2,)  # indexed


def test_fetch_after_part_of_a_set_was_read_keeps_the_rest_and_says_so():
    async def go():
        response, _ = live(samples.COUNTS, 4)
        async for rs in response:
            async for row in rs:
                break  # one row read live
            fetched = await response.fetch()
            return rs, [row async for row in rs], fetched

    current, rest, fetched = run(go())
    assert rest == [(3,), (4,)]  # the live response continues, reading from memory
    with pytest.raises(RowsNotAvailable, match="streamed past"):
        fetched.result_sets[0].rows


def test_finish_skips_rows_and_keeps_everything_else():
    async def go():
        response, _ = live(samples.COUNTS)
        await response.finish()
        return response

    response = run(go())
    assert [c.rows for c in response.completions] == [3, 2, 3, 3]
    with pytest.raises(RowsNotAvailable):
        response._reader.result_sets[0].rows


def test_returns_refuses_to_read_ahead_unless_told_how():
    async def go():
        response, _ = live(samples.EXEC_IN_BATCH)
        with pytest.raises(NotYetRead, match="Unread.KEEP"):
            await response.returns()
        returns = await response.returns(unread=Unread.KEEP)
        return returns, await read_all(response)

    returns, rows = run(go())
    assert returns[0].status == 5
    assert rows == [[(1,), (2,)], [(9,)]]  # KEEP kept everything, so reading can continue


def test_returns_with_discard_skips_rows():
    async def go():
        response, _ = live(samples.EXEC_IN_BATCH)
        returns = await response.returns(unread=Unread.DISCARD)
        return returns, response

    returns, response = run(go())
    assert returns[0].status == 5 and all(rs.rows_read for rs in response._reader.result_sets)


def test_errors_are_raised_at_the_end_once_with_the_whole_record():
    async def go():
        response, _ = live(samples.STATEMENT_FAILS)
        seen = []
        with pytest.raises(ServerError) as failed:
            async for rs in response:
                seen.append([row async for row in rs])
        await response.returns()  # already reported, so not raised again
        return seen, failed.value

    seen, error = run(go())
    assert seen == [[(1,)], [], [(2,)]]  # every result set first, then the error
    assert [e.number for e in error.errors] == [8134]
    assert isinstance(error.response, FetchedResponse) and len(error.response.result_sets) == 3
    assert [type(i).__name__ for i in error.response.sequence].count("Error") == 1


def test_fetch_raises_the_error_with_every_kept_row():
    async def go():
        response, _ = live(samples.BATCH_ENDS)
        await response.fetch()

    with pytest.raises(ServerError) as failed:
        run(go())
    assert failed.value.response.result_sets[0].rows == ((1,),)


def test_cancel_ends_the_owners_read_with_cancelled_and_the_record_shows_the_acknowledgement():
    async def go():
        response, source = live(samples.COUNTS, 8)
        await response._pull()
        response.cancel()  # as another task would
        response.cancel()  # safe to repeat
        with pytest.raises(Cancelled) as cancelled:
            await response.fetch()
        return response, source, cancelled.value

    response, source, cancelled = run(go())
    assert response.ended and source.after == []
    last = cancelled.response.completions[-1]
    assert DoneStatus.ATTENTION in last.status


def test_leaving_the_block_early_cancels_without_raising():
    async def go():
        response, _ = live(samples.COUNTS, 8)
        async with response:
            async for rs in response:
                break
        return response

    response = run(go())
    assert response.ended and response._reader.cancelled


def test_a_response_dropped_while_open_warns():
    response, _ = live(samples.COUNTS, 8)
    with pytest.warns(ResourceWarning, match="dropped while still open"):
        del response
        gc.collect()


def test_items_are_typed():
    r = reader(samples.STATEMENT_FAILS)
    assert isinstance(r.errors[0], Error) and not isinstance(r.errors[0], Message)
