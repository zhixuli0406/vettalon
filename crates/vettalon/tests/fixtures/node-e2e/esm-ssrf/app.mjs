export async function run(url) {
  const response = await fetch(url);
  return await response.text();
}
