package net.mullvad.mullvadvpn.ui.fragment

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.core.content.ContextCompat
import androidx.fragment.app.Fragment
import net.mullvad.mullvadvpn.R
import net.mullvad.mullvadvpn.ui.MainActivity
import net.mullvad.mullvadvpn.ui.NavigationBarPainter
import net.mullvad.mullvadvpn.ui.StatusBarPainter
import net.mullvad.mullvadvpn.ui.paintNavigationBar
import net.mullvad.mullvadvpn.ui.paintStatusBar

class LaunchFragment : Fragment(), StatusBarPainter, NavigationBarPainter {
    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View {
        val view = inflater.inflate(R.layout.launch, container, false)

        view.findViewById<View>(R.id.settings).setOnClickListener {
            (context as? MainActivity)?.openSettings()
        }

        context
            ?.let { ContextCompat.getColor(it, R.color.blue) }
            ?.let { color ->
                paintStatusBar(color)
                paintNavigationBar(color)
            }

        return view
    }
}