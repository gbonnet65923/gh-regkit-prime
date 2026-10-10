import React, { useEffect, useState } from "react";
import {
  Activity,
  Boxes,
  ExternalLink,
  FolderGit2,
  Heart,
  LogOut,
  Menu,
  Octagon,
  PanelLeftClose,
  PanelLeftOpen,
  Plus,
  Settings,
  ShieldCheck,
  X,
} from "lucide-react";
import { api, getToken, setToken } from "./api.js";
import StatusPanel from "./components/StatusPanel.jsx";
import ConfigPanel from "./components/ConfigPanel.jsx";
import AccountsPanel from "./components/AccountsPanel.jsx";
import {
  Badge,
  Button,
  Card,
  Dialog,
  Input,
  Spinner,
} from "./components/ui.jsx";

const NAV = [
  { id: "status", label: "Status", icon: Activity },
  { id: "config", label: "Config", icon: Settings },
  { id: "accounts", label: "Accounts", icon: Boxes },
];

export default function App() {
  const [auth, setAuth] = useState(null);
  const [tab, setTab] = useState("status");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [running, setRunning] = useState(false);
  const [sidebarOpen, setSidebarOpen] = useState(true);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [group, setGroup] = useState("");
  const [groups, setGroups] = useState([]);
  const [groupCreateOpen, setGroupCreateOpen] = useState(false);
  const [newGroupName, setNewGroupName] = useState("");
  const [groupBusy, setGroupBusy] = useState(false);
  const [groupDelete, setGroupDelete] = useState(null); // group name | null

  useEffect(() => {
    api
      .get("/api/config")
      .then((d) => setAuth({ needs: d.needs_auth }))
      .catch(() => setAuth({ needs: true }));
  }, []);
  useEffect(() => {
    if (auth?.needs && !getToken()) return undefined;
    const timer = setInterval(
      () =>
        api
          .get("/api/status")
          .then((d) => setRunning(!!d.running))
          .catch(() => {}),
      2500,
    );
    return () => clearInterval(timer);
  }, [auth]);

  function loadGroups() {
    api
      .get("/api/groups")
      .then((d) => setGroups(d.groups || []))
      .catch(() => {});
  }
  useEffect(() => {
    if (auth === null) return undefined;
    if (auth.needs && !getToken()) return undefined;
    loadGroups();
    const t = setInterval(loadGroups, 10000);
    return () => clearInterval(t);
  }, [auth]);

  function selectGroup(name) {
    setGroup(name);
    setTab("accounts");
    setDrawerOpen(false);
  }

  // Drawer is a mobile-only surface: close on Escape and when returning to desktop.
  useEffect(() => {
    if (!drawerOpen) return undefined;
    const onKeyDown = (e) => e.key === "Escape" && setDrawerOpen(false);
    const onResize = () => {
      if (window.innerWidth > 820) setDrawerOpen(false);
    };
    document.addEventListener("keydown", onKeyDown);
    window.addEventListener("resize", onResize);
    return () => {
      document.removeEventListener("keydown", onKeyDown);
      window.removeEventListener("resize", onResize);
    };
  }, [drawerOpen]);

  async function doCreateGroup() {
    const name = newGroupName.trim();
    if (!name || groupBusy) return;
    setGroupBusy(true);
    try {
      await api.post("/api/groups", { name });
      setGroupCreateOpen(false);
      setNewGroupName("");
      setGroup(name);
      setTab("accounts");
      loadGroups();
    } catch (e) {
      alert(`Failed to create group: ${e.message}`);
    } finally {
      setGroupBusy(false);
    }
  }

  async function doDeleteGroup() {
    const name = groupDelete;
    if (!name || groupBusy) return;
    setGroupBusy(true);
    try {
      await api.del(`/api/groups?name=${encodeURIComponent(name)}`);
      if (group === name) setGroup("");
      loadGroups();
    } catch (e) {
      alert(`Failed to delete group: ${e.message}`);
    } finally {
      setGroupBusy(false);
      setGroupDelete(null);
    }
  }

  async function doLogin() {
    try {
      const data = await api.post("/api/auth", { username, password });
      setToken(data.token);
      setAuth({ needs: data.needs_auth });
      setUsername("");
      setPassword("");
    } catch (error) {
      alert(`Login failed: ${error.message}`);
    }
  }

  if (auth === null)
    return (
      <main className="app-loading">
        <Spinner />
        <span>Loading application</span>
      </main>
    );
  if (auth.needs && !getToken())
    return (
      <main className="app-login">
        <Card className="app-login-card">
          <div className="app-login-mark">
            <ShieldCheck size={26} />
          </div>
          <h1>GitHub Register</h1>
          <p>Enter your username and password to open the console.</p>
          <Input
            type="text"
            placeholder="Username"
            autoComplete="username"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && doLogin()}
          />
          <Input
            type="password"
            placeholder="Password"
            autoComplete="current-password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && doLogin()}
          />
          <Button variant="primary" size="lg" onClick={doLogin}>
            Sign in
          </Button>
        </Card>
      </main>
    );

  const ActivePanel = {
    status: StatusPanel,
    config: ConfigPanel,
    accounts: AccountsPanel,
  }[tab];
  return (
    <div
      className={`${sidebarOpen ? "app-shell" : "app-shell app-shell-collapsed"}${drawerOpen ? " app-drawer-open" : ""}`}
    >
      {/* Mobile top bar: brand + job status + labeled menu (not a bare hamburger). */}
      <header className="app-topbar">
        <div className="app-topbar-brand">
          <div className="app-brand-icon">
            <Octagon size={18} />
          </div>
          <strong>GitHub Register</strong>
        </div>
        <div className="app-topbar-right">
          <Badge tone={running ? "success" : "muted"}>
            {running && <span className="pulse-dot" />}
            {running ? "Running" : "Idle"}
          </Badge>
          <Button
            variant="outline"
            className="app-menu-btn"
            onClick={() => setDrawerOpen(true)}
            aria-label="Open menu"
            aria-expanded={drawerOpen}
          >
            <Menu size={17} />
            <span>Menu</span>
          </Button>
        </div>
      </header>
      <div
        className="app-drawer-scrim"
        onClick={() => setDrawerOpen(false)}
        aria-hidden="true"
      />
      <aside
        className={
          sidebarOpen ? "app-sidebar" : "app-sidebar app-sidebar-collapsed"
        }
      >
        <div className="app-sidebar-top">
          <div className="app-brand">
            <div className="app-brand-icon">
              <Octagon size={20} />
            </div>
            <div className="app-brand-copy">
              <strong>GitHub Register</strong>
              <a
                className="app-brand-link"
                href="https://t.me/alstack"
                target="_blank"
                rel="noreferrer"
              >
                @alstack
              </a>
            </div>
          </div>
          <button
            type="button"
            className="app-drawer-close"
            onClick={() => setDrawerOpen(false)}
            aria-label="Close menu"
          >
            <X size={18} />
          </button>
          <Button
            variant="ghost"
            size="sm"
            className="app-sidebar-toggle"
            onClick={() => setSidebarOpen((open) => !open)}
            aria-label={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
            title={sidebarOpen ? "Collapse sidebar" : "Expand sidebar"}
          >
            {sidebarOpen ? (
              <PanelLeftClose size={17} />
            ) : (
              <PanelLeftOpen size={17} />
            )}
          </Button>
        </div>
        <nav className="app-nav">
          {NAV.map(({ id, label, icon: Icon }) => (
            <button
              key={id}
              className={tab === id ? "app-nav-item active" : "app-nav-item"}
              onClick={() => {
                setTab(id);
                setDrawerOpen(false);
                if (id === "accounts") setGroup("");
              }}
              title={label}
            >
              <Icon size={17} />
              <span>{label}</span>
            </button>
          ))}
          <div className="app-nav-groups">
            <div className="app-nav-label">
              <span>Groups</span>
              <button
                type="button"
                className="app-nav-add"
                onClick={() => {
                  setNewGroupName("");
                  setGroupCreateOpen(true);
                }}
                title="New group"
                aria-label="New group"
              >
                <Plus size={14} />
              </button>
            </div>
            {groups.map((g) => (
              <div key={g.name} className="app-group-row">
                <button
                  type="button"
                  className={
                    tab === "accounts" && group === g.name
                      ? "app-nav-item active"
                      : "app-nav-item"
                  }
                  onClick={() => selectGroup(g.name)}
                  title={`${g.name} · ${g.count} accounts`}
                >
                  <FolderGit2 size={16} />
                  <span className="app-group-name">{g.name}</span>
                  <span className="app-group-count">{g.count}</span>
                </button>
                <button
                  type="button"
                  className="app-group-del"
                  onClick={() => setGroupDelete(g.name)}
                  title={`Delete group ${g.name}`}
                  aria-label={`Delete group ${g.name}`}
                >
                  <X size={12} />
                </button>
              </div>
            ))}
            {groups.length === 0 && (
              <div className="app-nav-empty">No groups yet</div>
            )}
          </div>
        </nav>
        <div className="app-sidebar-footer">
          <Badge tone={running ? "success" : "muted"}>
            {running && <span className="pulse-dot" />}
            {running ? "Job running" : "Idle"}
          </Badge>
          {auth.needs && (
            <Button
              variant="ghost"
              size="sm"
              onClick={async () => {
                try {
                  await api.post("/api/logout", {});
                } catch {
                  /* expired token = already logged out, just clear local state */
                }
                setToken("");
                window.location.reload();
              }}
            >
              <LogOut size={14} /> <span>Sign out</span>
            </Button>
          )}
          <a
            className="app-support"
            href="https://t.me/alstack"
            target="_blank"
            rel="noreferrer"
            title="@alstack"
          >
            <Heart size={12} />
            <span>Telegram</span>
          </a>
          <a
            className="app-credit"
            href="https://github.com/gbonnet65923/gh-regkit-prime"
            target="_blank"
            rel="noreferrer"
            title="gbonnet65923/gh-regkit-prime"
          >
            <ExternalLink size={12} />
            <span>gh-regkit-prime</span>
          </a>
        </div>
      </aside>
      <main className="app-main" key={tab}>
        <ActivePanel
          onGotoAccounts={() => {
            setTab("accounts");
            setGroup("");
          }}
          onGotoStatus={() => {
            setTab("status");
          }}
          group={group}
          onClearGroup={() => setGroup("")}
          onGroupsChanged={loadGroups}
        />
      </main>

      {/* Mobile bottom nav: the three primary destinations, one thumb away. */}
      <nav className="app-bottomnav" aria-label="Primary">
        {NAV.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            type="button"
            className={
              tab === id
                ? "app-bottomnav-item active"
                : "app-bottomnav-item"
            }
            onClick={() => {
              setTab(id);
              if (id === "accounts") setGroup("");
            }}
            aria-current={tab === id ? "page" : undefined}
          >
            <Icon size={19} />
            <span>{label}</span>
          </button>
        ))}
      </nav>

      <Dialog
        open={groupCreateOpen}
        onClose={() => !groupBusy && setGroupCreateOpen(false)}
        title="New group"
        footer={
          <>
            <Button
              onClick={() => setGroupCreateOpen(false)}
              disabled={groupBusy}
            >
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={doCreateGroup}
              disabled={groupBusy || !newGroupName.trim()}
            >
              <Plus size={15} /> Create
            </Button>
          </>
        }
      >
        <div style={{ display: "grid", gap: 10 }}>
          <Input
            autoFocus
            value={newGroupName}
            onChange={(e) => setNewGroupName(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && doCreateGroup()}
            placeholder="Group name, e.g. Github"
            disabled={groupBusy}
          />
          <div style={{ fontSize: 12, color: "var(--text-muted)" }}>
            Only letters, digits, <code>-</code>, <code>_</code>, and{" "}
            <code>.</code> (maks 60 karakter).
          </div>
        </div>
      </Dialog>

      <Dialog
        open={!!groupDelete}
        onClose={() => setGroupDelete(null)}
        title="Delete this group?"
        footer={
          <>
            <Button onClick={() => setGroupDelete(null)}>Cancel</Button>
            <Button
              variant="destructive"
              onClick={doDeleteGroup}
              disabled={groupBusy}
            >
              <X size={15} /> Delete
            </Button>
          </>
        }
      >
        Group <strong>{groupDelete}</strong> will be deleted. Accounts inside
        are kept, only removed from the group.
      </Dialog>
    </div>
  );
}
