//! Checked byte access. Definitions, not this reader, assign meaning to bytes.
//! An incomplete read changes no external protocol state; callers may retry it.

use crate::{Error, ErrorKind, Result};

pub(crate) const MAX_PENDING: usize = 1024 * 1024;

pub(crate) struct Reader<'a> {
    bytes: &'a [u8],
    pub offset: usize,
    nodes: Option<Vec<crate::inspection::Node>>,
}
impl<'a> Reader<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Self {
            bytes,
            offset: 0,
            nodes: None,
        }
    }
    pub fn inspect(&mut self, enabled: bool) {
        self.nodes = enabled.then(Vec::new);
    }
    pub fn inspecting(&self) -> bool {
        self.nodes.is_some()
    }
    pub fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn at<T: std::fmt::Debug>(
        &mut self,
        offset: usize,
        name: &str,
        read: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        if offset > self.bytes.len() {
            return Err(Error::malformed(offset, "field offset"));
        }
        let saved = self.offset;
        self.offset = offset;
        let result = self.field(name, read);
        self.offset = saved;
        result
    }
    pub fn sensitive(&mut self) {
        if let Some(node) = self.nodes.as_mut().and_then(|ns| ns.last_mut()) {
            node.sensitive = true;
            node.raw.fill(0);
            node.shown = "[redacted]".into();
            node.children.clear();
        }
    }
    pub fn indexed<T: std::fmt::Debug>(
        &mut self,
        name: &str,
        index: usize,
        read: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        if !self.inspecting() {
            return read(self);
        }
        self.field(format!("{name} {index}"), read)
    }
    pub fn reference(&mut self, source: &'static str) {
        if let Some(node) = self.nodes.as_mut().and_then(|ns| ns.last_mut()) {
            node.source = Some(source);
        }
    }
    pub fn text(
        &mut self,
        name: &str,
        read: impl FnOnce(&mut Self) -> Result<crate::SqlText>,
    ) -> Result<crate::SqlText> {
        let result = self.field(name, read);
        if let Ok(text) = &result {
            self.show_text(text);
        }
        result
    }
    pub fn show_text(&mut self, text: &crate::SqlText) {
        if let Some(node) = self.nodes.as_mut().and_then(|ns| ns.last_mut())
            && let Ok(text) = text.to_string()
        {
            node.shown = crate::inspection::shown(&text);
        }
    }
    pub fn field<T: std::fmt::Debug>(
        &mut self,
        name: impl Into<String>,
        read: impl FnOnce(&mut Self) -> Result<T>,
    ) -> Result<T> {
        if self.nodes.is_none() {
            return read(self);
        }
        let parent = self.nodes.take();
        self.nodes = Some(Vec::new());
        let start = self.offset;
        let result = read(self);
        let children = self.nodes.take().unwrap();
        self.nodes = parent;
        let end = children
            .iter()
            .map(|n| n.range.end)
            .max()
            .unwrap_or(0)
            .max(self.offset);
        let mut node = crate::inspection::Node::new(
            name,
            crate::inspection::Basis::Token,
            start..end,
            &self.bytes[start..end],
        );
        node.children = children;
        match &result {
            Ok(value) => node.shown = crate::inspection::shown(value),
            Err(error) => node.issue = Some(error.to_string()),
        }
        self.nodes.as_mut().unwrap().push(node);
        result
    }
    pub fn adopt(&mut self, mut child: Reader<'_>, offset: usize) {
        if let Some(nodes) = &mut self.nodes {
            for mut node in child.nodes.take().unwrap_or_default() {
                node.shift(offset);
                nodes.push(node);
            }
        }
    }
    pub fn node(
        &mut self,
        name: &str,
        basis: crate::inspection::Basis,
        source: &'static str,
    ) -> Option<crate::inspection::Node> {
        let children = self.nodes.take()?;
        let end = children
            .iter()
            .map(|n| n.range.end)
            .max()
            .unwrap_or(0)
            .max(self.offset);
        let mut node = crate::inspection::Node::new(name, basis, 0..end, &self.bytes[..end]);
        node.children = children;
        node.basis(basis);
        node.source = Some(source);
        Some(node)
    }
    pub fn remaining(&self) -> usize {
        self.bytes.len() - self.offset
    }
    pub fn peek(&self) -> Option<u8> {
        self.bytes.get(self.offset).copied()
    }
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(n)
            .ok_or_else(|| Error::malformed(self.offset, "length"))?;
        let value = self.bytes.get(self.offset..end).ok_or_else(|| {
            Error::new(ErrorKind::Incomplete {
                offset: self.offset,
                needed: n,
            })
        })?;
        self.offset = end;
        Ok(value)
    }
    pub fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    pub fn u16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }
    pub fn be16(&mut self) -> Result<u16> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }
    pub fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn be32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
    }
    pub fn u64(&mut self) -> Result<u64> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }
    pub fn end(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::malformed(self.offset, "trailing bytes"))
        }
    }
}

pub(crate) fn append(pending: &mut Vec<u8>, data: &[u8]) -> Result<()> {
    if data.len() > MAX_PENDING.saturating_sub(pending.len()) {
        return Err(Error::new(ErrorKind::Limit(
            "pending protocol bytes (1 MiB)",
        )));
    }
    pending.extend_from_slice(data);
    Ok(())
}

pub(crate) fn utf16(text: &str) -> Vec<u8> {
    text.encode_utf16().flat_map(u16::to_le_bytes).collect()
}
