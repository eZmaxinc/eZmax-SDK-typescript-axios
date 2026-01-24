# CustomEzsignformfieldgroupRequest

A Custom Ezsignformfieldgroup Object to fill an Ezsignform using submitForm

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignformfieldgroupID** | **number** | The unique ID of the Ezsignformfieldgroup | [optional] [default to undefined]
**sEzsignformfieldgroupLabel** | **string** | The Label for the Ezsignformfieldgroup | [optional] [default to undefined]
**a_objEzsignformfield** | [**Array&lt;CustomEzsignformfieldRequest&gt;**](CustomEzsignformfieldRequest.md) | An array containing all the values to fill the Ezsignform. | [default to undefined]

## Example

```typescript
import { CustomEzsignformfieldgroupRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsignformfieldgroupRequest = {
    pkiEzsignformfieldgroupID,
    sEzsignformfieldgroupLabel,
    a_objEzsignformfield,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
