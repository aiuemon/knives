import {
	type PublicKeyCredentialCreationOptionsJSON,
	type PublicKeyCredentialRequestOptionsJSON,
	startAuthentication,
	startRegistration,
} from "@simplewebauthn/browser";
import { api } from "../api/client";

interface WebAuthnCeremonyResponse<T> {
	ceremony_id: string;
	options: T;
}

// パスキー登録(3.1節: ログイン済みユーザが追加登録するモデル)。
// begin/finishの間でceremony_idをクエリパラメータとして往復させ、
// finishのリクエストボディはブラウザの応答をそのまま送る
// (go-webauthnがRegistrationResponseJSONとしてパースできる形)。
export async function registerPasskey(): Promise<void> {
	const begin = await api.post<
		WebAuthnCeremonyResponse<PublicKeyCredentialCreationOptionsJSON>
	>("/auth/webauthn/register/begin");
	const attestation = await startRegistration({ optionsJSON: begin.options });
	await api.post(
		`/auth/webauthn/register/finish?ceremony_id=${encodeURIComponent(begin.ceremony_id)}`,
		attestation,
	);
}

// パスキーログイン(discoverable credential、メールアドレス入力不要)。
export async function loginWithPasskey(): Promise<void> {
	const begin = await api.post<
		WebAuthnCeremonyResponse<PublicKeyCredentialRequestOptionsJSON>
	>("/auth/webauthn/login/begin");
	const assertion = await startAuthentication({ optionsJSON: begin.options });
	await api.post(
		`/auth/webauthn/login/finish?ceremony_id=${encodeURIComponent(begin.ceremony_id)}`,
		assertion,
	);
}
