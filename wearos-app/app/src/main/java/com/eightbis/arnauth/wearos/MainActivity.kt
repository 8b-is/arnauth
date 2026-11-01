package com.eightbis.arnauth.wearos

import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.wear.compose.material3.Button
import androidx.wear.compose.material3.Card
import androidx.wear.compose.material3.Chip
import androidx.wear.compose.material3.Column
import androidx.wear.compose.material3.Scaffold
import androidx.wear.compose.material3.Text
import androidx.wear.compose.material3.Vignette
import androidx.wear.compose.material3.curvedComposable
import androidx.wear.compose.material3.rememberCurvedText
import androidx.wear.compose.material3.curvedRow
import androidx.wear.compose.material3.curvedText
import androidx.wear.compose.foundation.lazy.wear.listLazyColumnState
import androidx.wear.compose.foundation.lazy.wear.LazyColumn
import androidx.wear.compose.material3.TimeText
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.width
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Send
import androidx.compose.material.icons.filled.Person
import androidx.compose.material.icons.filled.Mail
import androidx.compose.material.icons.filled.Settings
import androidx.compose.material3.Icon
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch

class MainActivity : ComponentActivity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        enableEdgeToEdge()
        setContent { ArnauthScreen() }
    }
}

@Composable
fun ArnauthScreen() {
    val scope = rememberCoroutineScope()
    val identity by remember { mutableStateOf<String?>(null) }
    val peers by remember { mutableStateOf<List<String>>(emptyList()) }
    val messages by remember { mutableStateOf<List<String>>(emptyList()) }
    val status by remember { mutableStateOf("Initializing…") }

    // Load identity on start
    androidx.compose.runtime.LaunchedEffect(Unit) {
        loadIdentity()
    }

    Scaffold(
        timeText = { TimeText() },
        vignette = { Vignette(vignettePosition = 0.5f) },
        positionIndicator = {}
    ) { padding ->
        Box(modifier = Modifier.fillMaxSize().padding(padding)) {
            Column(
                modifier = Modifier.fillMaxSize(),
                verticalArrangement = Arrangement.spacedBy(8.dp),
                horizontalAlignment = Alignment.CenterHorizontally
            ) {
                // Header
                Text(
                    text = "Arnauth",
                    fontSize = 24.sp,
                    fontWeight = FontWeight.Bold,
                    color = Color.White
                )

                // Identity chip
                Chip(
                    onClick = { quickstart() },
                    modifier = Modifier.fillMaxWidth()
                ) {
                    Text(
                        text = identity ?: stringResource(R.string.no_identity),
                        fontSize = 14.sp,
                        maxLines = 1,
                        overflow = androidx.compose.ui.text.TextOverflow.Ellipsis
                    )
                }

                // Status
                Text(
                    text = status,
                    fontSize = 12.sp,
                    color = Color.Gray
                )

                Spacer(modifier = Modifier.size(8.dp))

                // Actions
                Column(modifier = Modifier.fillMaxWidth(), verticalArrangement = Arrangement.spacedBy(6.dp)) {
                    ActionChip(icon = Icons.Filled.Mail, label = "Inbox", onClick = { openInbox() })
                    ActionChip(icon = Icons.Filled.Send, label = "Send", onClick = { sendMessage() })
                    ActionChip(icon = Icons.Filled.Person, label = "Peers", onClick = { showPeers() })
                    ActionChip(icon = Icons.Filled.Settings, label = "Settings", onClick = { openSettings() })
                }
            }
        }
    }

    fun loadIdentity() {
        scope.launch(Dispatchers.IO) {
            status = "Loading identity…"
            try {
                val result = ArnauthBridge.whoami()
                identity = result.takeIf { it.isNotBlank() }
                status = if (identity != null) "Ready" else "No identity"
            } catch (e: Exception) {
                status = "Error: ${e.message}"
            }
        }
    }

    fun quickstart() {
        scope.launch(Dispatchers.IO) {
            status = "Quickstart…"
            try {
                val label = "watch.eth"
                ArnauthBridge.quickstart(label)
                identity = label
                status = "Ready: $label"
            } catch (e: Exception) {
                status = "Failed: ${e.message}"
            }
        }
    }

    fun openInbox() {
        scope.launch(Dispatchers.IO) {
            status = "Opening inbox…"
            try {
                val msgs = ArnauthBridge.inbox(take = true)
                messages = msgs
                status = "${msgs.size} message(s)"
            } catch (e: Exception) {
                status = "Error: ${e.message}"
            }
        }
    }

    fun sendMessage() {
        // TODO: Compose dialog for recipient + text
    }

    fun showPeers() {
        scope.launch(Dispatchers.IO) {
            try {
                val list = ArnauthBridge.swarmShow()
                peers = list
                status = "${list.size} peers"
            } catch (e: Exception) {
                status = "Error: ${e.message}"
            }
        }
    }

    fun openSettings() {
        // TODO
    }
}

@Composable
fun ActionChip(icon: androidx.compose.material.icons.Icons.Filled, label: String, onClick: () -> Unit) {
    Chip(onClick = onClick, modifier = Modifier.fillMaxWidth()) {
        androidx.compose.material3.Icon(imageVector = icon, contentDescription = null)
        androidx.compose.material3.Text(text = label, fontSize = 16.sp)
    }
}
