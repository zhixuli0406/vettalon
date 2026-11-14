import pg from 'pg';
export async function run(x) {
  const client = new pg.Client();
  return client.query("SELECT name FROM items WHERE name='" + x + "'");
}
