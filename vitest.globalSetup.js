import { MongoBinary } from 'mongodb-memory-server'

// download the MongoDB binary once, before the test files start in parallel and race on the same download
export default async function setup () {
  await MongoBinary.getPath()
}
