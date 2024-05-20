const deriveServerUrl = 'https://localhost:3000/api/derive';
const kyberServerUrl = 'https://localhost:3000/api/kyber';

export const $serverAPI = {
    derive: async (formBody) => {
        return fetch(`${deriveServerUrl}`, {
            method: 'POST',
            headers: {
                'Accept': '*/*',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                publicKey: formBody
            })
        }).then((response => {
            if (response.ok !== true) {
                return false;
            }
            else return response.json()
        }))
    },

    kyber: async (formBody) => {
        return fetch(`${kyberServerUrl}`, {
            method: 'POST',
            headers: {
                'Accept': '*/*',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                publicKey: formBody
            })
        }).then((response => {
            if (response.ok !== true) {
                return false;
            }
            else return response.json()
        }))
    }
}