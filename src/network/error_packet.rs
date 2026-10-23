use std::io::{Cursor, Seek, SeekFrom};

use byteorder::{LittleEndian, ReadBytesExt};

use crate::{binlog_error::BinlogError, ext::cursor_ext::CursorExt};

/// MySQL ERR packet（协议 0xFF 帧的解析结果）。
///
/// `error_code` / `sql_state` 为线上协议字段，解析保留以完整还原报文、
/// 供下游诊断使用；连接器自身目前只消费 `error_message`。
#[derive(Debug)]
#[allow(dead_code)] // 协议字段：保留完整性，非本连接器消费
pub struct ErrorPacket {
    pub error_code: u16,
    pub sql_state: String,
    pub error_message: String,
}

impl ErrorPacket {
    pub fn new(buf: &Vec<u8>) -> Result<Self, BinlogError> {
        let mut cursor = Cursor::new(buf);
        // the first byte is always 0xFF, which means it is an error packet
        cursor.seek(SeekFrom::Current(1))?;

        let error_code = cursor.read_u16::<LittleEndian>()?;
        let mut sql_state = "".to_string();

        if cursor.get_ref()[cursor.position() as usize] == b'#' {
            cursor.seek(SeekFrom::Current(1))?;
            sql_state = cursor.read_string(5)?;
        }

        let length = cursor.get_ref().len() - cursor.position() as usize;
        let error_message = cursor.read_string(length)?;

        Ok(Self {
            error_code,
            sql_state,
            error_message,
        })
    }
}
