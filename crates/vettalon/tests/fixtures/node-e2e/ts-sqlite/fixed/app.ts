import sqlite3 from 'sqlite3';
export function run(x: string): Promise<unknown> {
  const db = new sqlite3.Database(':memory:');
  return new Promise((resolve, reject) => {
    db.all('SELECT name FROM items WHERE name=?', [x], (error: Error | null, rows: unknown) => {
      if (error) reject(error); else resolve(rows);
    });
  });
}
