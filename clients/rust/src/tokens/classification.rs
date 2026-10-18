//! Negotiated DATACLASSIFICATION: labels, information types and optional ranks.
//! References within this token are checked before resolving the named subjects.
use super::*;
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label {
    pub name: SqlText,
    pub id: SqlText,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sensitivity {
    pub label: Option<Label>,
    pub information_type: Option<Label>,
    pub rank: Option<i32>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DataClassification {
    pub labels: Vec<Label>,
    pub information_types: Vec<Label>,
    pub rank: Option<i32>,
    pub columns: Vec<Vec<Sensitivity>>,
}
fn labels(r: &mut Reader<'_>) -> Result<Vec<Label>> {
    let n = r.u16()?;
    let mut labels = Vec::new();
    for _ in 0..n {
        labels.push(Label {
            name: short_text(r)?,
            id: short_text(r)?,
        });
    }
    Ok(labels)
}
fn reference(labels: &[Label], n: u16) -> Result<Option<Label>> {
    if n == u16::MAX {
        Ok(None)
    } else {
        labels
            .get(usize::from(n))
            .cloned()
            .map(Some)
            .ok_or_else(|| Error::malformed(0, "classification reference"))
    }
}
pub(super) fn read(r: &mut Reader<'_>, version: u8) -> Result<DataClassification> {
    if ![1, 2].contains(&version) {
        return Err(Error::malformed(
            0,
            "classification without negotiated version",
        ));
    }
    let labels = labels(r)?;
    let information_types = self::labels(r)?;
    let rank = if version >= 2 {
        Some(r.u32()? as i32)
    } else {
        None
    };
    let count = r.u16()?;
    if count > 4096 {
        return Err(Error::new(ErrorKind::Limit("classification column count")));
    }
    let mut columns = Vec::new();
    for _ in 0..count {
        let n = r.u16()?;
        let mut sensitivities = Vec::new();
        for _ in 0..n {
            let label = reference(&labels, r.u16()?)?;
            let information_type = reference(&information_types, r.u16()?)?;
            let rank = if version >= 2 {
                Some(r.u32()? as i32)
            } else {
                None
            };
            sensitivities.push(Sensitivity {
                label,
                information_type,
                rank,
            });
        }
        columns.push(sensitivities);
    }
    Ok(DataClassification {
        labels,
        information_types,
        rank,
        columns,
    })
}
