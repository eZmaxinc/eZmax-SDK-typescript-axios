# EzsignbulksendResponseCompoundV3

An Ezsignbulksend Object and children to create a complete structure

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignbulksendID** | **number** | The unique ID of the Ezsignbulksend | [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sLanguageNameX** | **string** | The Name of the Language in the language of the requester | [default to undefined]
**eEzsignbulksendEzsignformfieldorder** | [**FieldEEzsignbulksendEzsignformfieldorder**](FieldEEzsignbulksendEzsignformfieldorder.md) |  | [default to undefined]
**eEzsignfoldertypePrivacylevel** | [**FieldEEzsignfoldertypePrivacylevel**](FieldEEzsignfoldertypePrivacylevel.md) |  | [default to undefined]
**sEzsignfoldertypeNameX** | **string** | The name of the Ezsignfoldertype in the language of the requester | [default to undefined]
**sEzsignbulksendDescription** | **string** | The description of the Ezsignbulksend | [default to undefined]
**tEzsignbulksendNote** | **string** | Note about the Ezsignbulksend | [default to undefined]
**bEzsignbulksendNeedvalidation** | **boolean** | Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation | [default to undefined]
**bEzsignbulksendIsactive** | **boolean** | Whether the Ezsignbulksend is active or not | [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [default to undefined]
**a_objEzsignbulksenddocumentmapping** | [**Array&lt;EzsignbulksenddocumentmappingResponseCompound&gt;**](EzsignbulksenddocumentmappingResponseCompound.md) |  | [default to undefined]
**a_objEzsignbulksendsignermapping** | [**Array&lt;EzsignbulksendsignermappingResponse&gt;**](EzsignbulksendsignermappingResponse.md) |  | [default to undefined]

## Example

```typescript
import { EzsignbulksendResponseCompoundV3 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignbulksendResponseCompoundV3 = {
    pkiEzsignbulksendID,
    fkiEzsignfoldertypeID,
    fkiLanguageID,
    sLanguageNameX,
    eEzsignbulksendEzsignformfieldorder,
    eEzsignfoldertypePrivacylevel,
    sEzsignfoldertypeNameX,
    sEzsignbulksendDescription,
    tEzsignbulksendNote,
    bEzsignbulksendNeedvalidation,
    bEzsignbulksendIsactive,
    objAudit,
    a_objEzsignbulksenddocumentmapping,
    a_objEzsignbulksendsignermapping,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
