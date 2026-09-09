# ObjectAgentApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**agentBatchDownloadV1**](#agentbatchdownloadv1) | **POST** /1/object/agent/{pkiAgentID}/batchDownload | Download multiples attachments from a Agent|
|[**agentGetAttachmentsV1**](#agentgetattachmentsv1) | **GET** /1/object/agent/{pkiAgentID}/getAttachments | Retrieve Agent\&#39;s attachments|
|[**agentGetAutocompleteV2**](#agentgetautocompletev2) | **GET** /2/object/agent/getAutocomplete/{sSelector} | Retrieve Agents and IDs|
|[**agentGetListV1**](#agentgetlistv1) | **GET** /1/object/agent/getList | Retrieve Agent list|
|[**agentImportIntoEDMV1**](#agentimportintoedmv1) | **POST** /1/object/agent/{pkiAgentID}/importIntoEDM | Import attachments into the Agent|

# **agentBatchDownloadV1**
> File agentBatchDownloadV1(agentBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectAgentApi,
    Configuration,
    AgentBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAgentApi(configuration);

let pkiAgentID: number; // (default to undefined)
let agentBatchDownloadV1Request: AgentBatchDownloadV1Request; //

const { status, data } = await apiInstance.agentBatchDownloadV1(
    pkiAgentID,
    agentBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **agentBatchDownloadV1Request** | **AgentBatchDownloadV1Request**|  | |
| **pkiAgentID** | [**number**] |  | defaults to undefined|


### Return type

**File**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/zip, text/xml, application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **agentGetAttachmentsV1**
> AgentGetAttachmentsV1Response agentGetAttachmentsV1()


### Example

```typescript
import {
    ObjectAgentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAgentApi(configuration);

let pkiAgentID: number; // (default to undefined)

const { status, data } = await apiInstance.agentGetAttachmentsV1(
    pkiAgentID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiAgentID** | [**number**] |  | defaults to undefined|


### Return type

**AgentGetAttachmentsV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **agentGetAutocompleteV2**
> AgentGetAutocompleteV2Response agentGetAutocompleteV2()

Get the list of Agent to be used in a dropdown or autocomplete control.

### Example

```typescript
import {
    ObjectAgentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAgentApi(configuration);

let sSelector: 'All'; //The type of Agents to return (default to undefined)
let eFilterActive: 'All' | 'Active' | 'Inactive'; //Specify which results we want to display. (optional) (default to 'Active')
let sQuery: string; //Allow to filter the returned results (optional) (default to undefined)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)

const { status, data } = await apiInstance.agentGetAutocompleteV2(
    sSelector,
    eFilterActive,
    sQuery,
    acceptLanguage
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **sSelector** | [**&#39;All&#39;**]**Array<&#39;All&#39;>** | The type of Agents to return | defaults to undefined|
| **eFilterActive** | [**&#39;All&#39; | &#39;Active&#39; | &#39;Inactive&#39;**]**Array<&#39;All&#39; &#124; &#39;Active&#39; &#124; &#39;Inactive&#39;>** | Specify which results we want to display. | (optional) defaults to 'Active'|
| **sQuery** | [**string**] | Allow to filter the returned results | (optional) defaults to undefined|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|


### Return type

**AgentGetAutocompleteV2Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **agentGetListV1**
> AgentGetListV1Response agentGetListV1()



### Example

```typescript
import {
    ObjectAgentApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAgentApi(configuration);

let eOrderBy: 'pkiAgentID_ASC' | 'pkiAgentID_DESC' | 'fkiAgenttypeID_ASC' | 'fkiAgenttypeID_DESC' | 'sAgenttypeNameX_ASC' | 'sAgenttypeNameX_DESC' | 'fkiAgentincorporationID_ASC' | 'fkiAgentincorporationID_DESC' | 'sAgentincorporationName_ASC' | 'sAgentincorporationName_DESC' | 'fkiDepartmentID_ASC' | 'fkiDepartmentID_DESC' | 'sDepartmentNameX_ASC' | 'sDepartmentNameX_DESC' | 'fkiLanguageID_ASC' | 'fkiLanguageID_DESC' | 'sLanguageNameX_ASC' | 'sLanguageNameX_DESC' | 'sRealestateboardnumberNumber_ASC' | 'sRealestateboardnumberNumber_DESC' | 'sAgentCode_ASC' | 'sAgentCode_DESC' | 'iAgentPhotocopiercode_ASC' | 'iAgentPhotocopiercode_DESC' | 'iAgentLongdistancecode_ASC' | 'iAgentLongdistancecode_DESC' | 'iAgentBannernumber_ASC' | 'iAgentBannernumber_DESC' | 'sAgentRealestateassociationlicense_ASC' | 'sAgentRealestateassociationlicense_DESC' | 'dtAgentPermitexpiration_ASC' | 'dtAgentPermitexpiration_DESC' | 'dtAgentHiredate_ASC' | 'dtAgentHiredate_DESC' | 'dtAgentLeavedate_ASC' | 'dtAgentLeavedate_DESC' | 'bAgentTranquillit_ASC' | 'bAgentTranquillit_DESC' | 'bAgentResidentiallicense_ASC' | 'bAgentResidentiallicense_DESC' | 'bAgentCommerciallicense_ASC' | 'bAgentCommerciallicense_DESC' | 'bAgentMortgagelicense_ASC' | 'bAgentMortgagelicense_DESC' | 'bAgentPaidbyofficetranquillit_ASC' | 'bAgentPaidbyofficetranquillit_DESC' | 'dtAgentFintraccertification_ASC' | 'dtAgentFintraccertification_DESC' | 'sContactFirstname_ASC' | 'sContactFirstname_DESC' | 'sContactLastname_ASC' | 'sContactLastname_DESC' | 'dtContactBirthdate_ASC' | 'dtContactBirthdate_DESC' | 'sEmailAddress_ASC' | 'sEmailAddress_DESC' | 'sPhoneE164_ASC' | 'sPhoneE164_DESC' | 'sAddressCivic_ASC' | 'sAddressCivic_DESC' | 'sAddressStreet_ASC' | 'sAddressStreet_DESC' | 'sAddressSuite_ASC' | 'sAddressSuite_DESC' | 'sAddressCity_ASC' | 'sAddressCity_DESC' | 'sAddressZip_ASC' | 'sAddressZip_DESC' | 'sProvinceNameX_ASC' | 'sProvinceNameX_DESC' | 'sCountryNameX_ASC' | 'sCountryNameX_DESC' | 'bAgentIsactive_ASC' | 'bAgentIsactive_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.agentGetListV1(
    eOrderBy,
    iRowMax,
    iRowOffset,
    acceptLanguage,
    sFilter
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **eOrderBy** | [**&#39;pkiAgentID_ASC&#39; | &#39;pkiAgentID_DESC&#39; | &#39;fkiAgenttypeID_ASC&#39; | &#39;fkiAgenttypeID_DESC&#39; | &#39;sAgenttypeNameX_ASC&#39; | &#39;sAgenttypeNameX_DESC&#39; | &#39;fkiAgentincorporationID_ASC&#39; | &#39;fkiAgentincorporationID_DESC&#39; | &#39;sAgentincorporationName_ASC&#39; | &#39;sAgentincorporationName_DESC&#39; | &#39;fkiDepartmentID_ASC&#39; | &#39;fkiDepartmentID_DESC&#39; | &#39;sDepartmentNameX_ASC&#39; | &#39;sDepartmentNameX_DESC&#39; | &#39;fkiLanguageID_ASC&#39; | &#39;fkiLanguageID_DESC&#39; | &#39;sLanguageNameX_ASC&#39; | &#39;sLanguageNameX_DESC&#39; | &#39;sRealestateboardnumberNumber_ASC&#39; | &#39;sRealestateboardnumberNumber_DESC&#39; | &#39;sAgentCode_ASC&#39; | &#39;sAgentCode_DESC&#39; | &#39;iAgentPhotocopiercode_ASC&#39; | &#39;iAgentPhotocopiercode_DESC&#39; | &#39;iAgentLongdistancecode_ASC&#39; | &#39;iAgentLongdistancecode_DESC&#39; | &#39;iAgentBannernumber_ASC&#39; | &#39;iAgentBannernumber_DESC&#39; | &#39;sAgentRealestateassociationlicense_ASC&#39; | &#39;sAgentRealestateassociationlicense_DESC&#39; | &#39;dtAgentPermitexpiration_ASC&#39; | &#39;dtAgentPermitexpiration_DESC&#39; | &#39;dtAgentHiredate_ASC&#39; | &#39;dtAgentHiredate_DESC&#39; | &#39;dtAgentLeavedate_ASC&#39; | &#39;dtAgentLeavedate_DESC&#39; | &#39;bAgentTranquillit_ASC&#39; | &#39;bAgentTranquillit_DESC&#39; | &#39;bAgentResidentiallicense_ASC&#39; | &#39;bAgentResidentiallicense_DESC&#39; | &#39;bAgentCommerciallicense_ASC&#39; | &#39;bAgentCommerciallicense_DESC&#39; | &#39;bAgentMortgagelicense_ASC&#39; | &#39;bAgentMortgagelicense_DESC&#39; | &#39;bAgentPaidbyofficetranquillit_ASC&#39; | &#39;bAgentPaidbyofficetranquillit_DESC&#39; | &#39;dtAgentFintraccertification_ASC&#39; | &#39;dtAgentFintraccertification_DESC&#39; | &#39;sContactFirstname_ASC&#39; | &#39;sContactFirstname_DESC&#39; | &#39;sContactLastname_ASC&#39; | &#39;sContactLastname_DESC&#39; | &#39;dtContactBirthdate_ASC&#39; | &#39;dtContactBirthdate_DESC&#39; | &#39;sEmailAddress_ASC&#39; | &#39;sEmailAddress_DESC&#39; | &#39;sPhoneE164_ASC&#39; | &#39;sPhoneE164_DESC&#39; | &#39;sAddressCivic_ASC&#39; | &#39;sAddressCivic_DESC&#39; | &#39;sAddressStreet_ASC&#39; | &#39;sAddressStreet_DESC&#39; | &#39;sAddressSuite_ASC&#39; | &#39;sAddressSuite_DESC&#39; | &#39;sAddressCity_ASC&#39; | &#39;sAddressCity_DESC&#39; | &#39;sAddressZip_ASC&#39; | &#39;sAddressZip_DESC&#39; | &#39;sProvinceNameX_ASC&#39; | &#39;sProvinceNameX_DESC&#39; | &#39;sCountryNameX_ASC&#39; | &#39;sCountryNameX_DESC&#39; | &#39;bAgentIsactive_ASC&#39; | &#39;bAgentIsactive_DESC&#39;**]**Array<&#39;pkiAgentID_ASC&#39; &#124; &#39;pkiAgentID_DESC&#39; &#124; &#39;fkiAgenttypeID_ASC&#39; &#124; &#39;fkiAgenttypeID_DESC&#39; &#124; &#39;sAgenttypeNameX_ASC&#39; &#124; &#39;sAgenttypeNameX_DESC&#39; &#124; &#39;fkiAgentincorporationID_ASC&#39; &#124; &#39;fkiAgentincorporationID_DESC&#39; &#124; &#39;sAgentincorporationName_ASC&#39; &#124; &#39;sAgentincorporationName_DESC&#39; &#124; &#39;fkiDepartmentID_ASC&#39; &#124; &#39;fkiDepartmentID_DESC&#39; &#124; &#39;sDepartmentNameX_ASC&#39; &#124; &#39;sDepartmentNameX_DESC&#39; &#124; &#39;fkiLanguageID_ASC&#39; &#124; &#39;fkiLanguageID_DESC&#39; &#124; &#39;sLanguageNameX_ASC&#39; &#124; &#39;sLanguageNameX_DESC&#39; &#124; &#39;sRealestateboardnumberNumber_ASC&#39; &#124; &#39;sRealestateboardnumberNumber_DESC&#39; &#124; &#39;sAgentCode_ASC&#39; &#124; &#39;sAgentCode_DESC&#39; &#124; &#39;iAgentPhotocopiercode_ASC&#39; &#124; &#39;iAgentPhotocopiercode_DESC&#39; &#124; &#39;iAgentLongdistancecode_ASC&#39; &#124; &#39;iAgentLongdistancecode_DESC&#39; &#124; &#39;iAgentBannernumber_ASC&#39; &#124; &#39;iAgentBannernumber_DESC&#39; &#124; &#39;sAgentRealestateassociationlicense_ASC&#39; &#124; &#39;sAgentRealestateassociationlicense_DESC&#39; &#124; &#39;dtAgentPermitexpiration_ASC&#39; &#124; &#39;dtAgentPermitexpiration_DESC&#39; &#124; &#39;dtAgentHiredate_ASC&#39; &#124; &#39;dtAgentHiredate_DESC&#39; &#124; &#39;dtAgentLeavedate_ASC&#39; &#124; &#39;dtAgentLeavedate_DESC&#39; &#124; &#39;bAgentTranquillit_ASC&#39; &#124; &#39;bAgentTranquillit_DESC&#39; &#124; &#39;bAgentResidentiallicense_ASC&#39; &#124; &#39;bAgentResidentiallicense_DESC&#39; &#124; &#39;bAgentCommerciallicense_ASC&#39; &#124; &#39;bAgentCommerciallicense_DESC&#39; &#124; &#39;bAgentMortgagelicense_ASC&#39; &#124; &#39;bAgentMortgagelicense_DESC&#39; &#124; &#39;bAgentPaidbyofficetranquillit_ASC&#39; &#124; &#39;bAgentPaidbyofficetranquillit_DESC&#39; &#124; &#39;dtAgentFintraccertification_ASC&#39; &#124; &#39;dtAgentFintraccertification_DESC&#39; &#124; &#39;sContactFirstname_ASC&#39; &#124; &#39;sContactFirstname_DESC&#39; &#124; &#39;sContactLastname_ASC&#39; &#124; &#39;sContactLastname_DESC&#39; &#124; &#39;dtContactBirthdate_ASC&#39; &#124; &#39;dtContactBirthdate_DESC&#39; &#124; &#39;sEmailAddress_ASC&#39; &#124; &#39;sEmailAddress_DESC&#39; &#124; &#39;sPhoneE164_ASC&#39; &#124; &#39;sPhoneE164_DESC&#39; &#124; &#39;sAddressCivic_ASC&#39; &#124; &#39;sAddressCivic_DESC&#39; &#124; &#39;sAddressStreet_ASC&#39; &#124; &#39;sAddressStreet_DESC&#39; &#124; &#39;sAddressSuite_ASC&#39; &#124; &#39;sAddressSuite_DESC&#39; &#124; &#39;sAddressCity_ASC&#39; &#124; &#39;sAddressCity_DESC&#39; &#124; &#39;sAddressZip_ASC&#39; &#124; &#39;sAddressZip_DESC&#39; &#124; &#39;sProvinceNameX_ASC&#39; &#124; &#39;sProvinceNameX_DESC&#39; &#124; &#39;sCountryNameX_ASC&#39; &#124; &#39;sCountryNameX_DESC&#39; &#124; &#39;bAgentIsactive_ASC&#39; &#124; &#39;bAgentIsactive_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**AgentGetListV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json, application/vnd.openxmlformats-officedocument.spreadsheetml.sheet


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **agentImportIntoEDMV1**
> AgentImportIntoEDMV1Response agentImportIntoEDMV1(agentImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectAgentApi,
    Configuration,
    AgentImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectAgentApi(configuration);

let pkiAgentID: number; // (default to undefined)
let agentImportIntoEDMV1Request: AgentImportIntoEDMV1Request; //

const { status, data } = await apiInstance.agentImportIntoEDMV1(
    pkiAgentID,
    agentImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **agentImportIntoEDMV1Request** | **AgentImportIntoEDMV1Request**|  | |
| **pkiAgentID** | [**number**] |  | defaults to undefined|


### Return type

**AgentImportIntoEDMV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

