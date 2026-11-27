// Where generated CSV reports are kept.
//   REPORTS_BUCKET set (Floci/AWS): private S3 bucket, objects under reports/<userId>/<reportId>.csv,
//     downloaded through a 5-minute pre-signed URL; an S3 lifecycle rule deletes them after 30 days.
//   otherwise (local): kept in the PBReports store next to the metadata.
const URL_TTL_SEC = 300;
let clients = null;

function getClients() {
  if (clients) return clients;
  const { S3Client } = require('@aws-sdk/client-s3');
  const forcePathStyle = process.env.S3_FORCE_PATH_STYLE === 'true';
  clients = {
    s3: new S3Client({ forcePathStyle }),
    signer: process.env.S3_PUBLIC_ENDPOINT
      ? new S3Client({ endpoint: process.env.S3_PUBLIC_ENDPOINT, forcePathStyle: true })
      : new S3Client({ forcePathStyle })
  };
  return clients;
}

const usesS3 = () => Boolean(process.env.REPORTS_BUCKET);
const keyFor = (userId, reportId) => `reports/${userId}/${reportId}.csv`;

async function save(key, csv) {
  const { PutObjectCommand } = require('@aws-sdk/client-s3');
  await getClients().s3.send(new PutObjectCommand({
    Bucket: process.env.REPORTS_BUCKET, Key: key, Body: csv,
    ContentType: 'text/csv; charset=utf-8', ServerSideEncryption: 'AES256'
  }));
}

async function downloadUrl(key, filename) {
  const { GetObjectCommand } = require('@aws-sdk/client-s3');
  const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
  return getSignedUrl(getClients().signer, new GetObjectCommand({
    Bucket: process.env.REPORTS_BUCKET, Key: key,
    ResponseContentDisposition: `attachment; filename="${filename}"`
  }), { expiresIn: URL_TTL_SEC });
}

// Used by "download my data" (5f) to put the CSV text into the export.
async function read(key) {
  const { GetObjectCommand } = require('@aws-sdk/client-s3');
  const r = await getClients().s3.send(new GetObjectCommand({ Bucket: process.env.REPORTS_BUCKET, Key: key }));
  return r.Body.transformToString('utf-8');
}

async function remove(key) {
  const { DeleteObjectCommand } = require('@aws-sdk/client-s3');
  await getClients().s3.send(new DeleteObjectCommand({ Bucket: process.env.REPORTS_BUCKET, Key: key }));
}

module.exports = { usesS3, keyFor, save, read, downloadUrl, remove, URL_TTL_SEC };
