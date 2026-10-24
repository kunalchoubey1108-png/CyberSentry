// API base URL: the FastAPI backend at localhost:8000.
// Override with VITE_API_BASE when the API lives elsewhere.
export const API = import.meta.env.VITE_API_BASE || 'http://localhost:8000'

async function request(path, options = {}) {
  const response = await fetch(`${API}${path}`, options)
  let body = null
  try {
    body = await response.json()
  } catch {
    body = null
  }
  if (!response.ok) {
    const detail = body && body.detail ? body.detail : response.statusText
    throw new Error(`${response.status}: ${detail}`)
  }
  return body
}

export const getHealth = () => request('/health')
export const getIncidents = () => request('/incidents')
export const getIncident = (id) => request(`/incidents/${encodeURIComponent(id)}`)
export const createReport = (id) =>
  request(`/incidents/${encodeURIComponent(id)}/report`, { method: 'POST' })
export const getSamples = () => request('/samples')

export async function uploadFile(file) {
  const form = new FormData()
  form.append('file', file)
  return request('/upload', { method: 'POST', body: form })
}

export const fetchSample = async (name = 'sample_attacks.csv') => {
  const response = await fetch(`${API}/samples/${encodeURIComponent(name)}`)
  if (!response.ok) {
    throw new Error(`${response.status}: ${response.statusText}`)
  }
  return new File([await response.blob()], name, { type: 'text/csv' })
}