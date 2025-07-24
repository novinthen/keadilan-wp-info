import React, { useState, useEffect, useCallback } from 'react';
import { initializeApp } from 'firebase/app';
import { getAuth, signInWithEmailAndPassword, createUserWithEmailAndPassword, onAuthStateChanged, signOut, signInAnonymously, signInWithCustomToken, sendPasswordResetEmail } from 'firebase/auth';
import { getFirestore, doc, getDoc, setDoc, addDoc, collection, onSnapshot, query, where, getDocs, updateDoc, serverTimestamp, orderBy, limit } from 'firebase/firestore';
import { setLogLevel } from 'firebase/firestore';
import { useForm } from 'react-hook-form';
import * as yup from 'yup';
import { yupResolver } from '@hookform/resolvers/yup';
import { APP_ID, CABANGS, ROLES, PATHS } from './constants';

// --- Firebase Initialization ---
let firebaseConfig;
try {
    if (process.env.REACT_APP_FIREBASE_CONFIG) {
      firebaseConfig = JSON.parse(process.env.REACT_APP_FIREBASE_CONFIG);
    } else if (typeof __firebase_config !== 'undefined') {
      firebaseConfig = JSON.parse(__firebase_config);
    } else {
      console.warn("Firebase config not found in environment variables. This is expected for local development but will fail if deployed.");
      firebaseConfig = { apiKey: "INVALID_KEY" };
    }
} catch (e) {
    console.error("Could not parse Firebase config:", e);
    firebaseConfig = { apiKey: "INVALID_KEY" };
}

const app = initializeApp(firebaseConfig);
const auth = getAuth(app);
const db = getFirestore(app);
setLogLevel('debug');

// --- Helper to log activity ---
const logUserActivity = async (userId, type, details = {}) => {
    if (!userId) return;
    try {
        const logCollectionRef = collection(db, `${PATHS.USERS}/${userId}/activityLog`);
        await addDoc(logCollectionRef, {
            type,
            timestamp: serverTimestamp(),
            ipAddress: '127.0.0.1 (demo)',
            ...details,
        });
    } catch (error) {
        console.error("Error logging activity:", error);
    }
};

// --- Reusable NewsItem Component ---
function NewsItem({ newsItem, userId, copyToClipboard, isArchived = false }) {
    const [statement, setStatement] = useState(null);

    useEffect(() => {
        const statementRef = doc(db, `${PATHS.NEWS}/${newsItem.id}/statements`, userId);
        const unsubscribe = onSnapshot(statementRef, (docSnap) => {
            setStatement(docSnap.exists() ? docSnap.data() : null);
        });
        return () => unsubscribe();
    }, [newsItem.id, userId]);

    return (
        <div className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-2xl shadow-lg p-6 md:p-8 mb-6 transition-all hover:shadow-xl">
            <h3 className="text-2xl font-bold text-white mb-3">{newsItem.title}</h3>
            {isArchived && <p className="text-gray-200 text-sm mb-4">Published: {newsItem.createdAt?.toDate().toLocaleDateString()}</p>}
            <p className="text-gray-100 whitespace-pre-wrap mb-6 text-base">{newsItem.content}</p>
            <div className="bg-white/5 p-5 rounded-xl">
                <h4 className="text-lg font-semibold text-white mb-2">Your Statement:</h4>
                {statement && statement.newsId === newsItem.id ? (
                    <>
                        <p className="text-gray-100 whitespace-pre-wrap text-base mb-4">{statement.content}</p>
                        <button
                            onClick={() => copyToClipboard(statement.content, newsItem.id)}
                            className="px-4 py-2 bg-[#4FC3F7] hover:bg-[#ED1C24] text-white rounded-lg font-semibold text-sm transition-all duration-300 hover:scale-105"
                        >
                            Copy Statement
                        </button>
                    </>
                ) : (
                    <p className="text-gray-300 italic">No statement assigned.</p>
                )}
            </div>
        </div>
    );
}

// --- Main App Component ---
function AppContainer() {
    const [user, setUser] = useState(null);
    const [authReady, setAuthReady] = useState(false);
    const [userData, setUserData] = useState(null);
    const [view, setView] = useState('login');
    const [error, setError] = useState('');

    useEffect(() => {
        const unsubscribe = onAuthStateChanged(auth, async (firebaseUser) => {
            if (firebaseUser && !firebaseUser.isAnonymous) {
                const userDocRef = doc(db, PATHS.USERS, firebaseUser.uid);
                const userDocSnap = await getDoc(userDocRef);

                if (userDocSnap.exists()) {
                    const data = userDocSnap.data();
                    setUser(firebaseUser);
                    setUserData(data);
                    setView(data.isAdmin ? 'admin' : 'dashboard');
                    if (data.lastLogin === null || (serverTimestamp.now().seconds - data.lastLogin?.seconds > 60)) {
                        await updateDoc(userDocRef, { lastLogin: serverTimestamp() });
                        logUserActivity(firebaseUser.uid, 'LOGIN_SUCCESS');
                    }
                } else {
                    console.error("User document not found for UID:", firebaseUser.uid);
                    setError("Your user profile could not be found. Please contact an admin.");
                    await signOut(auth);
                }
            } else {
                setUser(null);
                setUserData(null);
                setView('login');
            }
            setAuthReady(true);
        });

        const performInitialSignIn = async () => {
            try {
                if (typeof __initial_auth_token !== 'undefined' && __initial_auth_token) {
                    await signInWithCustomToken(auth, __initial_auth_token);
                } else {
                    await signInAnonymously(auth);
                }
            } catch (err) {
                console.error("Error during initial sign-in:", err);
            }
        };
        performInitialSignIn();

        return () => unsubscribe();
    }, []);

    const handleLogin = useCallback(async (username, password) => {
        setError('');
        try {
            if (username.toLowerCase() === 'novinthen@gmail.com' && password === '123456789') {
                const adminEmail = 'admin@keadilan.local';
                try {
                    await signInWithEmailAndPassword(auth, adminEmail, password);
                } catch (error) {
                    if (error.code === 'auth/user-not-found') {
                        try {
                            const userCredential = await createUserWithEmailAndPassword(auth, adminEmail, password);
                            const adminUid = userCredential.user.uid;
                            await setDoc(doc(db, `${PATHS.USERS}`, adminUid), {
                                username: 'admin', role: 'Admin', cabang: 'HQ', isAdmin: true, createdAt: serverTimestamp(), lastLogin: null
                            });
                        } catch (creationError) {
                            console.error("Admin user creation failed:", creationError);
                            setError(`Admin account setup failed. Error code: ${creationError.code}`);
                        }
                    } else {
                        throw error;
                    }
                }
            } else {
                const email = username.toLowerCase().includes('@') ? username.toLowerCase() : `${username.toLowerCase()}@keadilan.local`;
                await signInWithEmailAndPassword(auth, email, password);
            }
        } catch (error) {
            console.error("Login Error:", error);
            setError(`Login failed. Error code: ${error.code}`);
        }
    }, []);

    const handleLogout = useCallback(async () => {
        if (user) {
            await logUserActivity(user.uid, 'LOGOUT');
        }
        await signOut(auth);
    }, [user]);

    if (!authReady) {
        return (
            <div className="flex items-center justify-center h-full">
                <div className="animate-spin rounded-full h-24 w-24 border-t-4 border-[#4FC3F7]"></div>
            </div>
        );
    }

    let currentView;
    switch (view) {
        case 'dashboard':
            currentView = <UserDashboard user={user} userData={userData} onLogout={handleLogout} />;
            break;
        case 'admin':
            currentView = <AdminDashboard onLogout={handleLogout} />;
            break;
        case 'login':
        default:
            currentView = <LoginScreen onLogin={handleLogin} error={error} />;
    }

    return (
        <div className="w-full h-full flex flex-col items-center justify-center">
            {currentView}
        </div>
    );
}

// --- Login Screen with Form Validation ---
const schema = yup.object({
    username: yup.string().required('Username is required'),
    password: yup.string().min(6, 'Password must be at least 6 characters').required('Password is required'),
});

function LoginScreen({ onLogin, error }) {
    const { register, handleSubmit, formState: { errors } } = useForm({
        resolver: yupResolver(schema),
    });

    return (
        <div className="w-full max-w-md p-8 md:p-10 space-y-6 bg-white/10 backdrop-blur-xl border border-white/20 rounded-2xl shadow-lg">
            <h2 className="text-3xl font-bold text-center text-white">Keadilan WP Info</h2>
            <p className="text-center text-gray-200 text-sm">Secure Campaign Portal</p>
            <form onSubmit={handleSubmit(({ username, password }) => onLogin(username, password))} className="space-y-5">
                <div>
                    <label className="block mb-1 text-sm font-medium text-gray-200">Username</label>
                    <input
                        {...register('username')}
                        placeholder="e.g., KC_KEPONG"
                        className="w-full px-4 py-2.5 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#4FC3F7] text-white text-sm"
                        aria-label="Username"
                    />
                    {errors.username && <p className="text-sm text-red-400 mt-1">{errors.username.message}</p>}
                </div>
                <div>
                    <label className="block mb-1 text-sm font-medium text-gray-200">Password</label>
                    <input
                        type="password"
                        {...register('password')}
                        placeholder="Password"
                        className="w-full px-4 py-2.5 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#4FC3F7] text-white text-sm"
                        aria-label="Password"
                    />
                    {errors.password && <p className="text-sm text-red-400 mt-1">{errors.password.message}</p>}
                </div>
                {error && <p className="text-sm text-center text-red-400 bg-red-900/30 p-3 rounded-lg">{error}</p>}
                <button
                    type="submit"
                    className="w-full px-4 py-3 text-sm font-bold text-white bg-[#4FC3F7] rounded-lg hover:bg-[#ED1C24] focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-offset-[#1A1A1A] focus:ring-white transition-all duration-300 hover:scale-105"
                    aria-label="Login to the platform"
                >
                    Login
                </button>
            </form>
        </div>
    );
}

// --- User Dashboard with Skeleton Loading ---
function UserDashboard({ user, userData, onLogout }) {
    const [latestNews, setLatestNews] = useState(null);
    const [archive, setArchive] = useState([]);
    const [loading, setLoading] = useState(true);
    const [showArchive, setShowArchive] = useState(false);

    useEffect(() => {
        const newsQuery = query(
            collection(db, PATHS.NEWS),
            orderBy('createdAt', 'desc'),
            limit(10)
        );
        const unsubscribeNews = onSnapshot(newsQuery, (querySnapshot) => {
            const newsItems = querySnapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            setLatestNews(newsItems[0] || null);
            setArchive(newsItems);
            setLoading(false);
        });
        return () => unsubscribeNews();
    }, []);

    const copyToClipboard = useCallback((text, newsId) => {
        const textArea = document.createElement("textarea");
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        try {
            document.execCommand('copy');
            alert('Statement copied to clipboard!');
            logUserActivity(user.uid, 'COPY_STATEMENT', { newsId, statementContent: text });
        } catch (err) {
            alert('Failed to copy text.');
        }
        document.body.removeChild(textArea);
    }, [user.uid]);

    if (loading) {
        return (
            <div className="w-full max-w-4xl space-y-4">
                <div className="h-8 bg-white/10 rounded-lg animate-pulse"></div>
                <div className="h-64 bg-white/10 rounded-lg animate-pulse"></div>
            </div>
        );
    }

    return (
        <div className="w-full max-w-4xl p-4 md:p-6">
            <header className="flex flex-col md:flex-row justify-between items-center mb-8 text-white">
                <div className="text-center md:text-left mb-4 md:mb-0">
                    <h1 className="text-3xl font-bold">Welcome, {userData.username}</h1>
                    <p className="text-lg text-gray-200">{userData.role} - {userData.cabang}</p>
                </div>
                <div className="flex items-center space-x-3">
                    <button
                        onClick={() => setShowArchive(!showArchive)}
                        className="px-4 py-2 bg-[#4FC3F7] hover:bg-[#ED1C24] text-white rounded-lg font-semibold text-sm transition-all duration-300 hover:scale-105"
                        aria-label={showArchive ? 'View latest news' : 'View archived news'}
                    >
                        {showArchive ? 'Latest News' : 'View Archive'}
                    </button>
                    <button
                        onClick={onLogout}
                        className="px-4 py-2 bg-[#ED1C24] hover:bg-[#4FC3F7] text-white rounded-lg font-semibold text-sm transition-all duration-300 hover:scale-105"
                        aria-label="Logout"
                    >
                        Logout
                    </button>
                </div>
            </header>
            <main>
                {!showArchive ? (
                    latestNews ? (
                        <>
                            <h2 className="text-2xl font-semibold text-white border-b-2 border-[#4FC3F7] pb-2 mb-6">Latest News & Task</h2>
                            <NewsItem newsItem={latestNews} userId={user.uid} copyToClipboard={copyToClipboard} />
                        </>
                    ) : (
                        <div className="text-center text-gray-200 text-lg p-8 bg-white/10 rounded-2xl shadow-lg">No news available.</div>
                    )
                ) : (
                    <>
                        <h2 className="text-2xl font-semibold text-white border-b-2 border-[#4FC3F7] pb-2 mb-6">Archived News</h2>
                        {archive.length > 0 ? (
                            archive.map(item => (
                                <NewsItem
                                    key={item.id}
                                    newsItem={item}
                                    userId={user.uid}
                                    copyToClipboard={copyToClipboard}
                                    isArchived={true}
                                />
                            ))
                        ) : (
                            <div className="text-center text-gray-200 text-lg p-8 bg-white/10 rounded-2xl shadow-lg">The archive is empty.</div>
                        )}
                    </>
                )}
            </main>
        </div>
    );
}

// --- Admin Dashboard with Responsive Sidebar ---
function AdminDashboard({ onLogout }) {
    const [adminView, setAdminView] = useState('users');
    const [isSidebarOpen, setIsSidebarOpen] = useState(false);

    return (
        <div className="flex min-h-screen w-full">
            <nav className={`fixed inset-y-0 left-0 w-64 bg-white/10 backdrop-blur-xl border-r border-white/20 p-6 flex flex-col transform ${isSidebarOpen ? 'translate-x-0' : '-translate-x-full'} md:translate-x-0 transition-transform duration-300 ease-in-out z-50`}>
                <button
                    className="md:hidden absolute top-4 right-4 text-white text-lg"
                    onClick={() => setIsSidebarOpen(false)}
                    aria-label="Close sidebar"
                >
                    ✕
                </button>
                <h1 className="text-2xl font-bold text-white mb-10">PKR Admin Panel</h1>
                <button
                    onClick={() => setAdminView('users')}
                    className={`w-full text-left p-3 rounded-lg mb-2 text-sm font-semibold transition-all ${adminView === 'users' ? 'bg-[#4FC3F7] text-white' : 'text-gray-200 hover:bg-white/20'}`}
                    aria-label="View user management"
                >
                    User Management
                </button>
                <button
                    onClick={() => setAdminView('news')}
                    className={`w-full text-left p-3 rounded-lg mb-2 text-sm font-semibold transition-all ${adminView === 'news' ? 'bg-[#4FC3F7] text-white' : 'text-gray-200 hover:bg-white/20'}`}
                    aria-label="View news and statements"
                >
                    News & Statements
                </button>
                <button
                    onClick={() => setAdminView('activity')}
                    className={`w-full text-left p-3 rounded-lg mb-2 text-sm font-semibold transition-all ${adminView === 'activity' ? 'bg-[#4FC3F7] text-white' : 'text-gray-200 hover:bg-white/20'}`}
                    aria-label="View user activity"
                >
                    User Activity
                </button>
                <div className="mt-auto">
                    <button
                        onClick={onLogout}
                        className="w-full p-3 rounded-lg bg-[#ED1C24] hover:bg-[#4FC3F7] text-white font-semibold text-sm transition-all duration-300 hover:scale-105"
                        aria-label="Logout"
                    >
                        Logout
                    </button>
                </div>
            </nav>
            <main className="flex-1 p-6 md:p-8 md:ml-64 bg-[#1A1A1A]/50">
                <button
                    className="md:hidden mb-4 px-4 py-2 bg-[#4FC3F7] hover:bg-[#ED1C24] text-white rounded-lg text-sm font-semibold transition-all duration-300"
                    onClick={() => setIsSidebarOpen(true)}
                    aria-label="Open sidebar"
                >
                    ☰ Menu
                </button>
                {adminView === 'users' && <UserManagement />}
                {adminView === 'news' && <NewsManagement />}
                {adminView === 'activity' && <UserActivityLog />}
            </main>
        </div>
    );
}

// --- User Management with Enhanced Table Styling ---
function UserManagement() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const usersQuery = query(collection(db, PATHS.USERS), where("isAdmin", "!=", true));
        const unsubscribe = onSnapshot(usersQuery, (snapshot) => {
            setUsers(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })));
            setLoading(false);
        });
        return () => unsubscribe();
    }, []);

    const handleCreateUsers = async () => {
        if (!window.confirm("This will create accounts for all predefined roles and cabangs. Passwords will match usernames (e.g., KC_KEPONG). Are you sure?")) return;
        alert("Starting user creation...");
        let createdCount = 0;
        for (const cabang of CABANGS) {
            for (const role of ROLES) {
                const username = `${role}_${cabang}`;
                const password = username;
                const email = `${username.toLowerCase()}@keadilan.local`;
                try {
                    const userQuery = query(collection(db, PATHS.USERS), where("username", "==", username));
                    if ((await getDocs(userQuery)).empty) {
                        const userCredential = await createUserWithEmailAndPassword(auth, email, password);
                        await setDoc(doc(db, PATHS.USERS, userCredential.user.uid), {
                            username, role, cabang, isAdmin: false, createdAt: serverTimestamp(), lastLogin: null
                        });
                        createdCount++;
                    }
                } catch (error) { console.error(`Failed to create user ${username}:`, error); }
            }
        }
        alert(`${createdCount} new users created successfully!`);
    };

    const handleAdminPasswordReset = async (username) => {
        if (!window.confirm(`Are you sure you want to send a password reset link to ${username}?`)) return;
        const email = `${username.toLowerCase()}@keadilan.local`;
        try {
            await sendPasswordResetEmail(auth, email);
            alert(`Password reset link sent for ${username}.`);
        } catch (error) {
            alert(`Failed to send reset link for ${username}.`);
            console.error(error);
        }
    };

    if (loading) {
        return (
            <div className="space-y-4">
                <div className="h-8 bg-white/10 rounded-lg animate-pulse"></div>
                <div className="h-64 bg-white/10 rounded-lg animate-pulse"></div>
            </div>
        );
    }

    return (
        <div>
            <h2 className="text-2xl font-bold mb-6 text-white">User Management</h2>
            <button
                onClick={handleCreateUsers}
                className="mb-6 px-4 py-2 bg-[#4FC3F7] hover:bg-[#ED1C24] text-white rounded-lg font-semibold text-sm transition-all duration-300 hover:scale-105"
                aria-label="Create all WP users"
            >
                Bulk Create Users
            </button>
            <div className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-xl p-6">
                <table className="w-full text-left text-sm">
                    <thead>
                        <tr className="border-b border-white/20 bg-[#4FC3F7]/10">
                            <th className="p-3 font-semibold text-white">Username</th>
                            <th className="p-3 font-semibold text-white">Role</th>
                            <th className="p-3 font-semibold text-white">Cabang</th>
                            <th className="p-3 font-semibold text-white">Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map((user, index) => (
                            <tr
                                key={user.id}
                                className={`border-b border-white/10 ${index % 2 === 0 ? 'bg-white/5' : 'bg-[#4FC3F7]/5'} hover:bg-[#ED1C24]/10 transition-all`}
                            >
                                <td className="p-3 text-gray-100">{user.username}</td>
                                <td className="p-3 text-gray-100">{user.role}</td>
                                <td className="p-3 text-gray-100">{user.cabang}</td>
                                <td className="p-3">
                                    <button
                                        onClick={() => handleAdminPasswordReset(user.username)}
                                        className="px-3 py-1.5 bg-[#ED1C24] hover:bg-[#4FC3F7] text-white rounded-lg text-sm font-semibold transition-all duration-300 hover:scale-105"
                                        aria-label={`Reset password for ${user.username}`}
                                    >
                                        Reset Password
                                    </button>
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

// --- News Management ---
function NewsManagement() {
    const [newsItems, setNewsItems] = useState([]);
    const [title, setTitle] = useState('');
    const [content, setContent] = useState('');
    const [selectedNewsId, setSelectedNewsId] = useState(null);

    useEffect(() => {
        const newsQuery = query(
            collection(db, PATHS.NEWS),
            orderBy('createdAt', 'desc'),
            limit(20)
        );
        const unsubscribe = onSnapshot(newsQuery, (snapshot) => {
            const items = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            setNewsItems(items);
        });
        return () => unsubscribe();
    }, []);

    const handlePublishNews = async (e) => {
        e.preventDefault();
        if (!title || !content) {
            alert("Title and content are required.");
            return;
        }
        try {
            await addDoc(collection(db, PATHS.NEWS), {
                title, content, createdAt: serverTimestamp(), archived: false
            });
            setTitle('');
            setContent('');
            alert("News published successfully!");
        } catch (error) {
            console.error("Error publishing news:", error);
            alert("Failed to publish news.");
        }
    };

    return (
        <div>
            <h2 className="text-2xl font-bold mb-6 text-white">News & Statements</h2>
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                <div className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-xl p-6">
                    <h3 className="text-lg font-bold mb-4 text-white">Publish News</h3>
                    <form onSubmit={handlePublishNews} className="space-y-4">
                        <input
                            type="text"
                            value={title}
                            onChange={e => setTitle(e.target.value)}
                            placeholder="News Title"
                            className="w-full px-4 py-2.5 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#4FC3F7] text-white text-sm"
                            aria-label="News title"
                        />
                        <textarea
                            value={content}
                            onChange={e => setContent(e.target.value)}
                            placeholder="News content..."
                            rows="6"
                            className="w-full px-4 py-2.5 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#4FC3F7] text-white text-sm"
                            aria-label="News content"
                        ></textarea>
                        <button
                            type="submit"
                            className="w-full px-4 py-2.5 text-sm font-bold text-white bg-[#4FC3F7] rounded-lg hover:bg-[#ED1C24] transition-all duration-300 hover:scale-105"
                            aria-label="Publish news"
                        >
                            Publish News
                        </button>
                    </form>
                </div>
                <div className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-xl p-6">
                    <h3 className="text-lg font-bold mb-4 text-white">Assign Statements</h3>
                    <div className="max-h-80 overflow-y-auto pr-2">
                        {newsItems.map(item => (
                            <div
                                key={item.id}
                                onClick={() => setSelectedNewsId(item.id)}
                                className={`p-3 rounded-lg mb-2 cursor-pointer transition-all ${selectedNewsId === item.id ? 'bg-[#4FC3F7] text-white' : 'bg-white/5 hover:bg-[#ED1C24]/10 text-gray-200'}`}
                            >
                                <p className="font-semibold text-sm">{item.title}</p>
                                <p className="text-xs text-gray-300">{item.createdAt?.toDate().toLocaleDateString()}</p>
                            </div>
                        ))}
                    </div>
                </div>
            </div>
            {selectedNewsId && <StatementAssigner newsId={selectedNewsId} />}
        </div>
    );
}

// --- Statement Assigner ---
function StatementAssigner({ newsId }) {
    const [users, setUsers] = useState([]);
    const [statements, setStatements] = useState({});

    useEffect(() => {
        const usersQuery = query(collection(db, PATHS.USERS), where("isAdmin", "!=", true));
        getDocs(usersQuery).then(snapshot => setUsers(snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }))));
        
        const statementsCollection = collection(db, `${PATHS.NEWS}/${newsId}/statements`);
        getDocs(statementsCollection).then(snapshot => {
            const existing = {};
            snapshot.forEach(doc => { existing[doc.id] = doc.data().content; });
            setStatements(existing);
        });
    }, [newsId]);

    const handleStatementChange = (userId, value) => setStatements(prev => ({ ...prev, [userId]: value }));

    const handleSaveStatements = async () => {
        if (!window.confirm("Save or update all statements for this news item?")) return;
        alert("Saving statements...");
        let successCount = 0;
        for (const userId in statements) {
            if (statements[userId]) {
                try {
                    await setDoc(doc(db, `${PATHS.NEWS}/${newsId}/statements`, userId), {
                        content: statements[userId], newsId, assignedAt: serverTimestamp()
                    });
                    successCount++;
                } catch (error) { console.error(`Failed to save for user ${userId}:`, error); }
            }
        }
        alert(`${successCount} statements saved successfully!`);
    };

    return (
        <div className="mt-6 bg-white/10 backdrop-blur-xl border border-white/20 rounded-xl p-6">
            <h3 className="text-lg font-bold mb-4 text-white">Assign Statements</h3>
            <div className="space-y-4 max-h-[50vh] overflow-y-auto pr-4">
                {users.map(user => (
                    <div key={user.id}>
                        <label className="block text-sm font-medium text-gray-200">{user.username} ({user.role})</label>
                        <textarea
                            value={statements[user.id] || ''}
                            onChange={e => handleStatementChange(user.id, e.target.value)}
                            placeholder={`Statement for ${user.username}...`}
                            rows="2"
                            className="w-full mt-1 px-4 py-2 bg-white/5 border border-white/20 rounded-lg focus:outline-none focus:ring-2 focus:ring-[#4FC3F7] text-white text-sm"
                            aria-label={`Statement for ${user.username}`}
                        />
                    </div>
                ))}
            </div>
            <button
                onClick={handleSaveStatements}
                className="mt-4 w-full px-4 py-2.5 text-sm font-bold text-white bg-[#4FC3F7] rounded-lg hover:bg-[#ED1C24] transition-all duration-300 hover:scale-105"
                aria-label="Save all statements"
            >
                Save Statements
            </button>
        </div>
    );
}

// --- User Activity Log with Enhanced Table Styling ---
function UserActivityLog() {
    const [users, setUsers] = useState([]);
    const [loading, setLoading] = useState(true);
    const [selectedUser, setSelectedUser] = useState(null);

    useEffect(() => {
        const usersQuery = query(collection(db, PATHS.USERS), where("isAdmin", "!=", true));
        const unsubscribe = onSnapshot(usersQuery, (snapshot) => {
            const userList = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            setUsers(userList.sort((a,b) => (b.lastLogin?.toMillis() || 0) - (a.lastLogin?.toMillis() || 0)));
            setLoading(false);
        });
        return () => unsubscribe();
    }, []);

    if (loading) {
        return (
            <div className="space-y-4">
                <div className="h-8 bg-white/10 rounded-lg animate-pulse"></div>
                <div className="h-64 bg-white/10 rounded-lg animate-pulse"></div>
            </div>
        );
    }

    if (selectedUser) {
        return <DetailedActivityView user={selectedUser} onBack={() => setSelectedUser(null)} />;
    }

    return (
        <div>
            <h2 className="text-2xl font-bold mb-6 text-white">User Activity Overview</h2>
            <div className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-xl p-6">
                <table className="w-full text-left text-sm">
                    <thead>
                        <tr className="border-b border-white/20 bg-[#4FC3F7]/10">
                            <th className="p-3 font-semibold text-white">Username</th>
                            <th className="p-3 font-semibold text-white">Last Login</th>
                            <th className="p-3 font-semibold text-white">IP Address (Demo)</th>
                            <th className="p-3 font-semibold text-white">Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {users.map((user, index) => (
                            <tr
                                key={user.id}
                                className={`border-b border-white/10 ${index % 2 === 0 ? 'bg-white/5' : 'bg-[#4FC3F7]/5'} hover:bg-[#ED1C24]/10 transition-all cursor-pointer`}
                                onClick={() => setSelectedUser(user)}
                            >
                                <td className="p-3 text-gray-100">{user.username}</td>
                                <td className="p-3 text-gray-100">{user.lastLogin ? user.lastLogin.toDate().toLocaleString() : 'Never'}</td>
                                <td className="p-3 text-gray-100">{user.ipAddress || 'N/A'}</td>
                                <td className="p-3 text-[#4FC3F7] hover:underline">View Log</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

// --- Detailed Activity View ---
function DetailedActivityView({ user, onBack }) {
    const [log, setLog] = useState([]);
    const [loading, setLoading] = useState(true);

    useEffect(() => {
        const logQuery = query(collection(db, `${PATHS.USERS}/${user.id}/activityLog`), orderBy('timestamp', 'desc'), limit(50));
        const unsubscribe = onSnapshot(logQuery, (snapshot) => {
            const logData = snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() }));
            setLog(logData);
            setLoading(false);
        });
        return () => unsubscribe();
    }, [user.id]);

    if (loading) {
        return (
            <div className="space-y-4">
                <div className="h-8 bg-white/10 rounded-lg animate-pulse"></div>
                <div className="h-64 bg-white/10 rounded-lg animate-pulse"></div>
            </div>
        );
    }

    return (
        <div>
            <button
                onClick={onBack}
                className="mb-6 px-4 py-2 bg-[#4FC3F7] hover:bg-[#ED1C24] text-white rounded-lg text-sm font-semibold transition-all duration-300 hover:scale-105"
                aria-label="Back to activity overview"
            >
                ← Back to Overview
            </button>
            <h2 className="text-2xl font-bold mb-2 text-white">Activity Log for {user.username}</h2>
            <p className="text-gray-200 mb-6 text-base">{user.role} - {user.cabang}</p>
            <div className="bg-white/10 backdrop-blur-xl border border-white/20 rounded-xl p-6">
                <table className="w-full text-left text-sm">
                    <thead>
                        <tr className="border-b border-white/20 bg-[#4FC3F7]/10">
                            <th className="p-3 font-semibold text-white">Timestamp</th>
                            <th className="p-3 font-semibold text-white">Event Type</th>
                            <th className="p-3 font-semibold text-white">Details</th>
                        </tr>
                    </thead>
                    <tbody>
                        {log.map((entry, index) => (
                            <tr
                                key={entry.id}
                                className={`border-b border-white/10 ${index % 2 === 0 ? 'bg-white/5' : 'bg-[#4FC3F7]/5'} hover:bg-[#ED1C24]/10 transition-all`}
                            >
                                <td className="p-3 text-gray-100">{entry.timestamp ? entry.timestamp.toDate().toLocaleString() : '...'}</td>
                                <td className="p-3">
                                    <span
                                        className={`px-3 py-1 text-xs font-semibold rounded-full ${entry.type === 'LOGIN_SUCCESS' ? 'bg-[#4FC3F7] text-white' : entry.type === 'LOGOUT' ? 'bg-[#ED1C24] text-white' : 'bg-white/20 text-white'}`}
                                    >
                                        {entry.type}
                                    </span>
                                </td>
                                <td className="p-3 text-gray-100">{entry.newsId ? `News ID: ${entry.newsId.substring(0,10)}...` : entry.ipAddress || ''}</td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}

// --- Root Component ---
export default function Root() {
    return (
        <div className="min-h-screen w-full bg-gradient-to-br from-[#ED1C24] to-[#4FC3F7] text-white font-sans flex flex-col items-center p-4 sm:p-6 lg:p-8">
            <h1 className="text-4xl md:text-5xl font-bold text-white my-6 text-center drop-shadow-lg">PKR Campaign Platform</h1>
            <main className="w-full h-full flex-1 flex flex-col items-center justify-center">
                <AppContainer />
            </main>
            <footer className="w-full text-center py-4 text-gray-200 text-sm mt-6">
                ©2025 Parti Keadilan Rakyat
            </footer>
        </div>
    );
}
