# CustomEzsigndocumentRequest

Request for POST /2/object/ezsignfolder/{pkiEzsignfolderID}/reorder

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [default to undefined]
**a_objEzsigndocumentdependency** | [**Array&lt;EzsigndocumentdependencyRequestCompound&gt;**](EzsigndocumentdependencyRequestCompound.md) |  | [default to undefined]

## Example

```typescript
import { CustomEzsigndocumentRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsigndocumentRequest = {
    pkiEzsigndocumentID,
    a_objEzsigndocumentdependency,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
