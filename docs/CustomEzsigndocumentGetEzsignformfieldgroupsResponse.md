# CustomEzsigndocumentGetEzsignformfieldgroupsResponse

An Ezsigndocument Object in the context of a getEzsignformfieldgroups path

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [default to undefined]
**sEzsigndocumentName** | **string** | The name of the document that will be presented to Ezsignfoldersignerassociations | [default to undefined]
**a_objEzsignformfieldgroup** | [**Array&lt;EzsignformfieldgroupResponseCompound&gt;**](EzsignformfieldgroupResponseCompound.md) |  | [default to undefined]

## Example

```typescript
import { CustomEzsigndocumentGetEzsignformfieldgroupsResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsigndocumentGetEzsignformfieldgroupsResponse = {
    pkiEzsigndocumentID,
    sEzsigndocumentName,
    a_objEzsignformfieldgroup,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
