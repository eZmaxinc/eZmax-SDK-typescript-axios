# EzsigntemplateResponseCompound

A Ezsigntemplate Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [default to undefined]
**fkiEzsigntemplatedocumentID** | **number** | The unique ID of the Ezsigntemplatedocument | [optional] [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**fkiEzdoctemplatedocumentID** | **number** | The unique ID of the Ezdoctemplatedocument | [optional] [default to undefined]
**sLanguageNameX** | **string** | The Name of the Language in the language of the requester | [default to undefined]
**sEzsigntemplateDescription** | **string** | The description of the Ezsigntemplate | [default to undefined]
**sEzsigntemplateExternaldescription** | **string** | The external description of the Ezsigntemplate | [optional] [default to undefined]
**tEzsigntemplateComment** | **string** | The comment of the Ezsigntemplate | [optional] [default to undefined]
**sEzsigntemplateFilenamepattern** | **string** | The filename pattern of the Ezsigntemplate | [optional] [default to undefined]
**bEzsigntemplateAdminonly** | **boolean** | Whether the Ezsigntemplate can be accessed by admin users only (eUserType&#x3D;Normal) | [default to undefined]
**sEzsignfoldertypeNameX** | **string** | The name of the Ezsignfoldertype in the language of the requester | [optional] [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [default to undefined]
**bEzsigntemplateEditallowed** | **boolean** | Whether the Ezsigntemplate if allowed to edit or not | [default to undefined]
**eEzsigntemplateType** | [**FieldEEzsigntemplateType**](FieldEEzsigntemplateType.md) |  | [optional] [default to undefined]
**objEzsigntemplatedocument** | [**EzsigntemplatedocumentResponse**](EzsigntemplatedocumentResponse.md) |  | [optional] [default to undefined]
**a_objEzsigntemplatesigner** | [**Array&lt;EzsigntemplatesignerResponseCompound&gt;**](EzsigntemplatesignerResponseCompound.md) |  | [default to undefined]
**a_objEzsigntemplateannotation** | [**Array&lt;EzsigntemplateannotationResponseCompound&gt;**](EzsigntemplateannotationResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsigntemplateResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplateResponseCompound = {
    pkiEzsigntemplateID,
    fkiEzsigntemplatedocumentID,
    fkiEzsignfoldertypeID,
    fkiLanguageID,
    fkiEzdoctemplatedocumentID,
    sLanguageNameX,
    sEzsigntemplateDescription,
    sEzsigntemplateExternaldescription,
    tEzsigntemplateComment,
    sEzsigntemplateFilenamepattern,
    bEzsigntemplateAdminonly,
    sEzsignfoldertypeNameX,
    objAudit,
    bEzsigntemplateEditallowed,
    eEzsigntemplateType,
    objEzsigntemplatedocument,
    a_objEzsigntemplatesigner,
    a_objEzsigntemplateannotation,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
