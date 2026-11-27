# ObjectDisclosureApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**disclosureBatchDownloadV1**](#disclosurebatchdownloadv1) | **POST** /1/object/disclosure/{pkiDisclosureID}/batchDownload | Download multiples attachments from a Disclosure|
|[**disclosureGetAttachmentsV1**](#disclosuregetattachmentsv1) | **GET** /1/object/disclosure/{pkiDisclosureID}/getAttachments | Retrieve Disclosure\&#39;s attachments|
|[**disclosureGetCommunicationCountV1**](#disclosuregetcommunicationcountv1) | **GET** /1/object/disclosure/{pkiDisclosureID}/getCommunicationCount | Retrieve Communication count|
|[**disclosureGetCommunicationListV1**](#disclosuregetcommunicationlistv1) | **GET** /1/object/disclosure/{pkiDisclosureID}/getCommunicationList | Retrieve Communication list|
|[**disclosureGetCommunicationrecipientsV1**](#disclosuregetcommunicationrecipientsv1) | **GET** /1/object/disclosure/{pkiDisclosureID}/getCommunicationrecipients | Retrieve Communication recipients|
|[**disclosureGetCommunicationsendersV1**](#disclosuregetcommunicationsendersv1) | **GET** /1/object/disclosure/{pkiDisclosureID}/getCommunicationsenders | Retrieve Communication senders|
|[**disclosureGetListV1**](#disclosuregetlistv1) | **GET** /1/object/disclosure/getList | Retrieve Disclosure list|
|[**disclosureImportIntoEDMV1**](#disclosureimportintoedmv1) | **POST** /1/object/disclosure/{pkiDisclosureID}/importIntoEDM | Import attachments into the Disclosure|

# **disclosureBatchDownloadV1**
> File disclosureBatchDownloadV1(disclosureBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectDisclosureApi,
    Configuration,
    DisclosureBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDisclosureApi(configuration);

let pkiDisclosureID: number; // (default to undefined)
let disclosureBatchDownloadV1Request: DisclosureBatchDownloadV1Request; //

const { status, data } = await apiInstance.disclosureBatchDownloadV1(
    pkiDisclosureID,
    disclosureBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **disclosureBatchDownloadV1Request** | **DisclosureBatchDownloadV1Request**|  | |
| **pkiDisclosureID** | [**number**] |  | defaults to undefined|


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
|**406** | The URL is valid, but one of the Accept header is not defined or invalid. For example, you set the header \&quot;Accept: application/json\&quot; but the function can only return \&quot;Content-type: image/png\&quot; |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body. |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **disclosureGetAttachmentsV1**
> DisclosureGetAttachmentsV1Response disclosureGetAttachmentsV1()


### Example

```typescript
import {
    ObjectDisclosureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDisclosureApi(configuration);

let pkiDisclosureID: number; // (default to undefined)

const { status, data } = await apiInstance.disclosureGetAttachmentsV1(
    pkiDisclosureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDisclosureID** | [**number**] |  | defaults to undefined|


### Return type

**DisclosureGetAttachmentsV1Response**

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

# **disclosureGetCommunicationCountV1**
> DisclosureGetCommunicationCountV1Response disclosureGetCommunicationCountV1()


### Example

```typescript
import {
    ObjectDisclosureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDisclosureApi(configuration);

let pkiDisclosureID: number; // (default to undefined)

const { status, data } = await apiInstance.disclosureGetCommunicationCountV1(
    pkiDisclosureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDisclosureID** | [**number**] |  | defaults to undefined|


### Return type

**DisclosureGetCommunicationCountV1Response**

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

# **disclosureGetCommunicationListV1**
> DisclosureGetCommunicationListV1Response disclosureGetCommunicationListV1()


### Example

```typescript
import {
    ObjectDisclosureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDisclosureApi(configuration);

let pkiDisclosureID: number; // (default to undefined)

const { status, data } = await apiInstance.disclosureGetCommunicationListV1(
    pkiDisclosureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDisclosureID** | [**number**] |  | defaults to undefined|


### Return type

**DisclosureGetCommunicationListV1Response**

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

# **disclosureGetCommunicationrecipientsV1**
> DisclosureGetCommunicationrecipientsV1Response disclosureGetCommunicationrecipientsV1()


### Example

```typescript
import {
    ObjectDisclosureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDisclosureApi(configuration);

let pkiDisclosureID: number; // (default to undefined)

const { status, data } = await apiInstance.disclosureGetCommunicationrecipientsV1(
    pkiDisclosureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDisclosureID** | [**number**] |  | defaults to undefined|


### Return type

**DisclosureGetCommunicationrecipientsV1Response**

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

# **disclosureGetCommunicationsendersV1**
> DisclosureGetCommunicationsendersV1Response disclosureGetCommunicationsendersV1()


### Example

```typescript
import {
    ObjectDisclosureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDisclosureApi(configuration);

let pkiDisclosureID: number; // (default to undefined)

const { status, data } = await apiInstance.disclosureGetCommunicationsendersV1(
    pkiDisclosureID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDisclosureID** | [**number**] |  | defaults to undefined|


### Return type

**DisclosureGetCommunicationsendersV1Response**

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

# **disclosureGetListV1**
> DisclosureGetListV1Response disclosureGetListV1()

Enum values that can be filtered in query parameter *sFilter*:  | Variable | Valid values | |---|---| | eDisclosureInteresttype | Direct<br>Indirect |

### Example

```typescript
import {
    ObjectDisclosureApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDisclosureApi(configuration);

let eOrderBy: 'pkiDisclosureID_ASC' | 'pkiDisclosureID_DESC' | 'fkiAgentID_ASC' | 'fkiAgentID_DESC' | 'fkiBrokerID_ASC' | 'fkiBrokerID_DESC' | 'eDisclosureInteresttype_ASC' | 'eDisclosureInteresttype_DESC' | 'sDisclosureRelation_ASC' | 'sDisclosureRelation_DESC' | 'dtDisclosureRedactiondate_ASC' | 'dtDisclosureRedactiondate_DESC' | 'dtDisclosureAcceptationdate_ASC' | 'dtDisclosureAcceptationdate_DESC' | 'dtDisclosureReceptiondate_ASC' | 'dtDisclosureReceptiondate_DESC' | 'bDisclosureIsactive_ASC' | 'bDisclosureIsactive_DESC' | 'sDisclosureNumber_ASC' | 'sDisclosureNumber_DESC' | 'sContactFirstname_ASC' | 'sContactFirstname_DESC' | 'sContactLastname_ASC' | 'sContactLastname_DESC' | 'sBrokerName_ASC' | 'sBrokerName_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.disclosureGetListV1(
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
| **eOrderBy** | [**&#39;pkiDisclosureID_ASC&#39; | &#39;pkiDisclosureID_DESC&#39; | &#39;fkiAgentID_ASC&#39; | &#39;fkiAgentID_DESC&#39; | &#39;fkiBrokerID_ASC&#39; | &#39;fkiBrokerID_DESC&#39; | &#39;eDisclosureInteresttype_ASC&#39; | &#39;eDisclosureInteresttype_DESC&#39; | &#39;sDisclosureRelation_ASC&#39; | &#39;sDisclosureRelation_DESC&#39; | &#39;dtDisclosureRedactiondate_ASC&#39; | &#39;dtDisclosureRedactiondate_DESC&#39; | &#39;dtDisclosureAcceptationdate_ASC&#39; | &#39;dtDisclosureAcceptationdate_DESC&#39; | &#39;dtDisclosureReceptiondate_ASC&#39; | &#39;dtDisclosureReceptiondate_DESC&#39; | &#39;bDisclosureIsactive_ASC&#39; | &#39;bDisclosureIsactive_DESC&#39; | &#39;sDisclosureNumber_ASC&#39; | &#39;sDisclosureNumber_DESC&#39; | &#39;sContactFirstname_ASC&#39; | &#39;sContactFirstname_DESC&#39; | &#39;sContactLastname_ASC&#39; | &#39;sContactLastname_DESC&#39; | &#39;sBrokerName_ASC&#39; | &#39;sBrokerName_DESC&#39;**]**Array<&#39;pkiDisclosureID_ASC&#39; &#124; &#39;pkiDisclosureID_DESC&#39; &#124; &#39;fkiAgentID_ASC&#39; &#124; &#39;fkiAgentID_DESC&#39; &#124; &#39;fkiBrokerID_ASC&#39; &#124; &#39;fkiBrokerID_DESC&#39; &#124; &#39;eDisclosureInteresttype_ASC&#39; &#124; &#39;eDisclosureInteresttype_DESC&#39; &#124; &#39;sDisclosureRelation_ASC&#39; &#124; &#39;sDisclosureRelation_DESC&#39; &#124; &#39;dtDisclosureRedactiondate_ASC&#39; &#124; &#39;dtDisclosureRedactiondate_DESC&#39; &#124; &#39;dtDisclosureAcceptationdate_ASC&#39; &#124; &#39;dtDisclosureAcceptationdate_DESC&#39; &#124; &#39;dtDisclosureReceptiondate_ASC&#39; &#124; &#39;dtDisclosureReceptiondate_DESC&#39; &#124; &#39;bDisclosureIsactive_ASC&#39; &#124; &#39;bDisclosureIsactive_DESC&#39; &#124; &#39;sDisclosureNumber_ASC&#39; &#124; &#39;sDisclosureNumber_DESC&#39; &#124; &#39;sContactFirstname_ASC&#39; &#124; &#39;sContactFirstname_DESC&#39; &#124; &#39;sContactLastname_ASC&#39; &#124; &#39;sContactLastname_DESC&#39; &#124; &#39;sBrokerName_ASC&#39; &#124; &#39;sBrokerName_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**DisclosureGetListV1Response**

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

# **disclosureImportIntoEDMV1**
> DisclosureImportIntoEDMV1Response disclosureImportIntoEDMV1(disclosureImportIntoEDMV1Request)


### Example

```typescript
import {
    ObjectDisclosureApi,
    Configuration,
    DisclosureImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDisclosureApi(configuration);

let pkiDisclosureID: number; // (default to undefined)
let disclosureImportIntoEDMV1Request: DisclosureImportIntoEDMV1Request; //

const { status, data } = await apiInstance.disclosureImportIntoEDMV1(
    pkiDisclosureID,
    disclosureImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **disclosureImportIntoEDMV1Request** | **DisclosureImportIntoEDMV1Request**|  | |
| **pkiDisclosureID** | [**number**] |  | defaults to undefined|


### Return type

**DisclosureImportIntoEDMV1Response**

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

