# EzsigndocumentSubmitEzsignformV1Request

Request for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/submitEzsignform

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bEzsignformIsdraft** | **boolean** | Whether the Ezsignform submitted is a draft or not. | [default to undefined]
**a_objEzsignformfieldgroup** | [**Array&lt;CustomEzsignformfieldgroupRequest&gt;**](CustomEzsignformfieldgroupRequest.md) |  | [default to undefined]

## Example

```typescript
import { EzsigndocumentSubmitEzsignformV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentSubmitEzsignformV1Request = {
    bEzsignformIsdraft,
    a_objEzsignformfieldgroup,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
