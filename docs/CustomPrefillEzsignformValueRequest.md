# CustomPrefillEzsignformValueRequest

A Custom PrefillEzsignformValue Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sEzsignformfieldgroupLabel** | **string** | The Label for the Ezsignformfieldgroup | [default to undefined]
**sEzsignformfieldLabel** | **string** | The Label for the Ezsignformfield | [optional] [default to undefined]
**sEzsignformfieldEnteredvalue** | **string** | This is the value enterred for the Ezsignformfield  This can only be set if eEzsignformfieldgroupType is **Dropdown**, **Text** or **Textarea** | [optional] [default to undefined]
**bEzsignformfieldSelected** | **boolean** | Whether the Ezsignformfield is selected or not by default.  This can only be set if eEzsignformfieldgroupType is **Checkbox** or **Radio** | [optional] [default to undefined]

## Example

```typescript
import { CustomPrefillEzsignformValueRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomPrefillEzsignformValueRequest = {
    sEzsignformfieldgroupLabel,
    sEzsignformfieldLabel,
    sEzsignformfieldEnteredvalue,
    bEzsignformfieldSelected,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
