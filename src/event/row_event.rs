use std::io::Cursor;

use serde::{Deserialize, Serialize};

use crate::{
    binlog_error::BinlogError,
    column::{column_type::ColumnType, column_value::ColumnValue},
    ext::cursor_ext::CursorExt,
};

use super::table_map_event::TableMapEvent;

#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct RowEvent {
    pub column_values: Vec<ColumnValue>,
}

impl RowEvent {
    #[allow(clippy::needless_range_loop)]
    pub fn parse(
        cursor: &mut Cursor<&Vec<u8>>,
        table_map_event: &TableMapEvent,
        included_columns: &[bool],
    ) -> Result<Self, BinlogError> {
        // Per MySQL binlog spec, the null bitmap covers only the columns present
        // in the event (bits set in included_columns), NOT all table columns.
        // Sizing it by included_columns.len() over-reads when binlog_row_image=MINIMAL
        // (or any partial column set) leaves gaps, shifting every following byte
        // and eventually hitting EOF.
        let included_column_count = included_columns.iter().filter(|&&b| b).count();
        let null_columns = cursor.read_bits(included_column_count, false)?;
        let mut column_values = Vec::with_capacity(table_map_event.column_types.len());
        let mut skipped_column_count = 0;
        for i in 0..table_map_event.column_types.len() {
            if !included_columns[i] {
                skipped_column_count += 1;
                column_values.push(ColumnValue::None);
                continue;
            }

            let index = i - skipped_column_count;
            if null_columns[index] {
                column_values.push(ColumnValue::None);
                continue;
            }

            let column_meta = table_map_event.column_metas[i];
            let mut column_type = table_map_event.column_types[i];
            let mut column_length = column_meta;

            if column_type == ColumnType::String as u8 && column_meta >= 256 {
                (column_type, column_length) =
                    ColumnType::parse_string_column_meta(column_meta, column_type)?;
            }

            let col_value = ColumnValue::parse(
                cursor,
                ColumnType::from_code(column_type),
                column_meta,
                column_length,
            )?;
            column_values.push(col_value);
        }

        Ok(Self { column_values })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn null_bitmap_uses_only_included_columns() {
        let table_map = TableMapEvent {
            table_id: 42,
            database_name: "test".to_string(),
            table_name: "items".to_string(),
            column_types: vec![
                ColumnType::Long as u8,
                ColumnType::Long as u8,
                ColumnType::Long as u8,
            ],
            column_metas: vec![0, 0, 0],
            null_bits: vec![true, true, true],
            table_metadata: None,
        };
        let included_columns = vec![true, false, true];
        // The two included columns need a one-byte NULL bitmap. The second
        // included column is NULL, followed only by the first LONG value.
        let data = vec![0b0000_0010, 42, 0, 0, 0];
        let mut cursor = Cursor::new(&data);

        let row = RowEvent::parse(&mut cursor, &table_map, &included_columns).unwrap();

        assert_eq!(
            row.column_values,
            vec![ColumnValue::Long(42), ColumnValue::None, ColumnValue::None]
        );
        assert_eq!(cursor.position(), data.len() as u64);
    }
}
