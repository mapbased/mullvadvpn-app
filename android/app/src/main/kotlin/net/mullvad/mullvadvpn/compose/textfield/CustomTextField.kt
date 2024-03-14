package net.mullvad.mullvadvpn.compose.textfield

import android.text.TextUtils
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.text.KeyboardActions
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.material3.TextField
import androidx.compose.runtime.Composable
import androidx.compose.runtime.SideEffect
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.rememberCoroutineScope
import androidx.compose.runtime.setValue
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.text.TextRange
import androidx.compose.ui.text.input.ImeAction
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.input.TextFieldValue
import androidx.compose.ui.text.input.VisualTransformation
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import net.mullvad.mullvadvpn.constant.EMPTY_STRING
import net.mullvad.mullvadvpn.constant.NEWLINE_STRING

@Composable
fun CustomTextField(
    value: String,
    keyboardType: KeyboardType,
    modifier: Modifier = Modifier,
    onValueChanged: (String) -> Unit,
    onSubmit: (String) -> Unit,
    isEnabled: Boolean = true,
    placeholderText: String?,
    maxCharLength: Int = Int.MAX_VALUE,
    isValidValue: Boolean,
    isDigitsOnlyAllowed: Boolean,
    visualTransformation: VisualTransformation = VisualTransformation.None
) {

    val scope = rememberCoroutineScope()

    // This is the same implementation as in BasicTextField.kt but with initial selection set at the
    // end of the text rather than in the beginning.
    // This is a fix for https://issuetracker.google.com/issues/272693535.
    var textFieldValueState by remember {
        mutableStateOf(TextFieldValue(text = value, selection = TextRange(value.length)))
    }
    val textFieldValue = textFieldValueState.copy(text = value)
    SideEffect {
        if (
            textFieldValue.selection != textFieldValueState.selection ||
                textFieldValue.composition != textFieldValueState.composition
        ) {
            textFieldValueState = textFieldValue
        }
    }
    var lastTextValue by remember(value) { mutableStateOf(value) }

    TextField(
        value = textFieldValue,
        onValueChange = { newTextFieldValueState ->
            textFieldValueState = newTextFieldValueState

            val stringChangedSinceLastInvocation = lastTextValue != newTextFieldValueState.text
            lastTextValue = newTextFieldValueState.text

            if (stringChangedSinceLastInvocation) {
                val isValidInput =
                    if (isDigitsOnlyAllowed) TextUtils.isDigitsOnly(newTextFieldValueState.text)
                    else true
                if (newTextFieldValueState.text.length <= maxCharLength && isValidInput) {
                    // Remove any newline chars added by enter key clicks
                    onValueChanged(
                        newTextFieldValueState.text.replace(NEWLINE_STRING, EMPTY_STRING)
                    )
                }
            }
        },
        enabled = isEnabled,
        singleLine = true,
        placeholder = placeholderText?.let { { Text(text = it) } },
        keyboardOptions =
            KeyboardOptions(
                keyboardType = keyboardType,
                imeAction = ImeAction.Done,
                autoCorrect = false,
            ),
        keyboardActions =
            KeyboardActions(
                onDone = {
                    scope.launch {
                        // https://issuetracker.google.com/issues/305518328
                        delay(100)
                        onSubmit(value)
                    }
                }
            ),
        visualTransformation = visualTransformation,
        colors = mullvadDarkTextFieldColors(),
        isError = !isValidValue,
        modifier = modifier.clip(MaterialTheme.shapes.small).fillMaxWidth()
    )
}
