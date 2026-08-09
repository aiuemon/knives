import { Route, Routes } from "react-router-dom";
import { AdminRoute } from "./components/AdminRoute";
import { ProtectedRoute } from "./components/ProtectedRoute";
import { AdminSettingsPage } from "./pages/AdminSettingsPage";
import { AdminUsersPage } from "./pages/AdminUsersPage";
import { ConfirmLinkPage } from "./pages/ConfirmLinkPage";
import { DashboardPage } from "./pages/DashboardPage";
import { LoginPage } from "./pages/LoginPage";
import { PendingLinksPage } from "./pages/PendingLinksPage";
import { SignupPage } from "./pages/SignupPage";
import { VerifyEmailPage } from "./pages/VerifyEmailPage";

function App() {
	return (
		<Routes>
			<Route path="/login" element={<LoginPage />} />
			<Route path="/signup" element={<SignupPage />} />
			<Route path="/auth/local/verify-email" element={<VerifyEmailPage />} />
			<Route path="/auth/confirm-link" element={<ConfirmLinkPage />} />
			<Route
				path="/"
				element={
					<ProtectedRoute>
						<DashboardPage />
					</ProtectedRoute>
				}
			/>
			<Route
				path="/pending-links"
				element={
					<ProtectedRoute>
						<PendingLinksPage />
					</ProtectedRoute>
				}
			/>
			<Route
				path="/admin/settings"
				element={
					<AdminRoute>
						<AdminSettingsPage />
					</AdminRoute>
				}
			/>
			<Route
				path="/admin/users"
				element={
					<AdminRoute>
						<AdminUsersPage />
					</AdminRoute>
				}
			/>
		</Routes>
	);
}

export default App;
