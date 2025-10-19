# CustomEzsignformfieldRequest

A Custom Ezsignformfield Object to fill an Ezsignform using submitForm

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignformfieldID** | **number** | The unique ID of the Ezsignformfield | [optional] [default to undefined]
**sEzsignformfieldLabel** | **string** | The Label for the Ezsignformfield | [optional] [default to undefined]
**bEzsignformfieldSelected** | **boolean** | Whether the Ezsignformfield is selected or not by default.  This can only be set if eEzsignformfieldgroupType is **Checkbox** or **Radio** | [optional] [default to undefined]
**sEzsignformfieldEnteredvalue** | **string** | This is the value enterred for the Ezsignformfield  This can only be set if eEzsignformfieldgroupType is **Dropdown**, **Text** or **Textarea** | [optional] [default to undefined]

## Example

```typescript
import { CustomEzsignformfieldRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsignformfieldRequest = {
    pkiEzsignformfieldID,
    sEzsignformfieldLabel,
    bEzsignformfieldSelected,
    sEzsignformfieldEnteredvalue,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
