#include<bits/stdc++.h>
using namespace std;

unordered_map<char, int> alph = {
    {'R', 0}, {'P', 1}, {'S', 2}, {'L', 3}, {'V', 4}
};
vector<char> alph1 = {'R', 'P', 'S', 'L', 'V'};
vector<vector<int>> v = {
    {  0, -1,  1,  1, -1 }, // R
    {  1,  0, -1, -1,  1 }, // P
    { -1,  1,  0,  1, -1 }, // S
    { -1,  1, -1,  0,  1 }, // L
    {  1, -1,  1, -1,  0 }, // V
};
vector<pair<int, int>> win = { // per battere X usa Y/Z
    {1, 4}, // R
    {2, 3}, // P
    {0, 4}, // S
    {0, 2}, // L
    {1, 3}, // V
};
vector<int> idx;
vector<vector<array<int, 5>>> mm;

int point(int me, int opp) {
    return v[me][opp] == 1 ? 1 : 0;
}

int dp(int pos, int m, int curr) {
    if(pos == idx.size())
        return 0;
    int &res = mm[pos][m][curr];
    if(res != -1)
        return res;
    int best = dp(pos + 1, m, curr) + point(curr, idx[pos]);
    if(m > 0) {
        for(int nxt = 0; nxt < 5; nxt++) {
            if(nxt == curr) continue;
            best = max(best, dp(pos + 1, m - 1, nxt) + point(nxt, idx[pos]));
        }
    }
    return res = best;
}

int main() {
    string s; cin >> s;
    int n, m; cin >> n >> m;
    assert(n == s.size());

    for(char a : s) {
        idx.push_back(alph[a]);
    }

    mm.assign(n + 1, vector<array<int, 5>>(m + 1));
    for(int i = 0; i <= n; i++) {
        for(int j = 0; j <= m; j++) {
            mm[i][j].fill(-1);
        }
    }

    int curr = 0;
    int best = dp(0, m, 0);
    for(int i=1; i<5; i++) {
        int t = dp(0, m, i);
        if(t > best) {
            best = t;
            curr = i;
        }
    }

    for(int i=0; i<n; i++) {
        int chosen = curr;
        int best_here = point(curr, idx[i]) + dp(i + 1, m, curr);

        if(m > 0) {
            for(int nxt = 0; nxt < 5; nxt++) {
                if(nxt == curr) continue;
                int cand = point(nxt, idx[i]) + dp(i + 1, m - 1, nxt);
                if(cand > best_here) {
                    best_here = cand;
                    chosen = nxt;
                }
            }
        }

        if(chosen != curr) {
            m--;
            curr = chosen;
        }
        cout << alph1[curr];
    }
    cout << "\n";

    return 0;
}
