# ObjectElectronicfundstransferApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**electronicfundstransferBatchDownloadV1**](#electronicfundstransferbatchdownloadv1) | **POST** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/batchDownload | Download multiples attachments from an Electronicfundstransfer|
|[**electronicfundstransferGetAttachmentsV1**](#electronicfundstransfergetattachmentsv1) | **GET** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getAttachments | Retrieve Electronicfundstransfer\&#39;s attachments|
|[**electronicfundstransferGetCommunicationCountV1**](#electronicfundstransfergetcommunicationcountv1) | **GET** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationCount | Retrieve Communication count|
|[**electronicfundstransferGetCommunicationListV1**](#electronicfundstransfergetcommunicationlistv1) | **GET** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationList | Retrieve Communication list|
|[**electronicfundstransferGetCommunicationrecipientsV1**](#electronicfundstransfergetcommunicationrecipientsv1) | **GET** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationrecipients | Retrieve Electronicfundstransfer\&#39;s Communicationrecipient|
|[**electronicfundstransferGetCommunicationsendersV1**](#electronicfundstransfergetcommunicationsendersv1) | **GET** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/getCommunicationsenders | Retrieve Electronicfundstransfer\&#39;s Communicationsender|
|[**electronicfundstransferGetListV1**](#electronicfundstransfergetlistv1) | **GET** /1/object/electronicfundstransfer/getList | Retrieve Electronicfundstransfer list|
|[**electronicfundstransferImportIntoEDMV1**](#electronicfundstransferimportintoedmv1) | **POST** /1/object/electronicfundstransfer/{pkiElectronicfundstransferID}/importIntoEDM | Import attachments into the Electronicfundstransfer|

# **electronicfundstransferBatchDownloadV1**
> File electronicfundstransferBatchDownloadV1(electronicfundstransferBatchDownloadV1Request)


### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration,
    ElectronicfundstransferBatchDownloadV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)
let electronicfundstransferBatchDownloadV1Request: ElectronicfundstransferBatchDownloadV1Request; //

const { status, data } = await apiInstance.electronicfundstransferBatchDownloadV1(
    pkiElectronicfundstransferID,
    electronicfundstransferBatchDownloadV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **electronicfundstransferBatchDownloadV1Request** | **ElectronicfundstransferBatchDownloadV1Request**|  | |
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


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

# **electronicfundstransferGetAttachmentsV1**
> ElectronicfundstransferGetAttachmentsV1Response electronicfundstransferGetAttachmentsV1()


### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)

const { status, data } = await apiInstance.electronicfundstransferGetAttachmentsV1(
    pkiElectronicfundstransferID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


### Return type

**ElectronicfundstransferGetAttachmentsV1Response**

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

# **electronicfundstransferGetCommunicationCountV1**
> ElectronicfundstransferGetCommunicationCountV1Response electronicfundstransferGetCommunicationCountV1()



### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)

const { status, data } = await apiInstance.electronicfundstransferGetCommunicationCountV1(
    pkiElectronicfundstransferID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


### Return type

**ElectronicfundstransferGetCommunicationCountV1Response**

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

# **electronicfundstransferGetCommunicationListV1**
> ElectronicfundstransferGetCommunicationListV1Response electronicfundstransferGetCommunicationListV1()



### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)

const { status, data } = await apiInstance.electronicfundstransferGetCommunicationListV1(
    pkiElectronicfundstransferID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


### Return type

**ElectronicfundstransferGetCommunicationListV1Response**

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

# **electronicfundstransferGetCommunicationrecipientsV1**
> ElectronicfundstransferGetCommunicationrecipientsV1Response electronicfundstransferGetCommunicationrecipientsV1()



### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)

const { status, data } = await apiInstance.electronicfundstransferGetCommunicationrecipientsV1(
    pkiElectronicfundstransferID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


### Return type

**ElectronicfundstransferGetCommunicationrecipientsV1Response**

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

# **electronicfundstransferGetCommunicationsendersV1**
> ElectronicfundstransferGetCommunicationsendersV1Response electronicfundstransferGetCommunicationsendersV1()



### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)

const { status, data } = await apiInstance.electronicfundstransferGetCommunicationsendersV1(
    pkiElectronicfundstransferID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


### Return type

**ElectronicfundstransferGetCommunicationsendersV1Response**

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

# **electronicfundstransferGetListV1**
> ElectronicfundstransferGetListV1Response electronicfundstransferGetListV1()



### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let eOrderBy: 'pkiElectronicfundstransferID_ASC' | 'pkiElectronicfundstransferID_DESC' | 'fkiPaymentmethodID_ASC' | 'fkiPaymentmethodID_DESC' | 'fkiUserIDCreated_ASC' | 'fkiUserIDCreated_DESC' | 'sPaymentmethodDescriptionX_ASC' | 'sPaymentmethodDescriptionX_DESC' | 'sUserLoginnameCreated_ASC' | 'sUserLoginnameCreated_DESC' | 'iElectronicfundstransferNumber_ASC' | 'iElectronicfundstransferNumber_DESC' | 'dtElectronicfundstransferDate_ASC' | 'dtElectronicfundstransferDate_DESC' | 'iElectronicfundstransferTransactioncount_ASC' | 'iElectronicfundstransferTransactioncount_DESC' | 'dElectronicfundstransferAmountvisible_ASC' | 'dElectronicfundstransferAmountvisible_DESC'; //Specify how you want the results to be sorted (optional) (default to undefined)
let iRowMax: number; // (optional) (default to undefined)
let iRowOffset: number; // (optional) (default to 0)
let acceptLanguage: HeaderAcceptLanguage; // (optional) (default to undefined)
let sFilter: string; // (optional) (default to undefined)

const { status, data } = await apiInstance.electronicfundstransferGetListV1(
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
| **eOrderBy** | [**&#39;pkiElectronicfundstransferID_ASC&#39; | &#39;pkiElectronicfundstransferID_DESC&#39; | &#39;fkiPaymentmethodID_ASC&#39; | &#39;fkiPaymentmethodID_DESC&#39; | &#39;fkiUserIDCreated_ASC&#39; | &#39;fkiUserIDCreated_DESC&#39; | &#39;sPaymentmethodDescriptionX_ASC&#39; | &#39;sPaymentmethodDescriptionX_DESC&#39; | &#39;sUserLoginnameCreated_ASC&#39; | &#39;sUserLoginnameCreated_DESC&#39; | &#39;iElectronicfundstransferNumber_ASC&#39; | &#39;iElectronicfundstransferNumber_DESC&#39; | &#39;dtElectronicfundstransferDate_ASC&#39; | &#39;dtElectronicfundstransferDate_DESC&#39; | &#39;iElectronicfundstransferTransactioncount_ASC&#39; | &#39;iElectronicfundstransferTransactioncount_DESC&#39; | &#39;dElectronicfundstransferAmountvisible_ASC&#39; | &#39;dElectronicfundstransferAmountvisible_DESC&#39;**]**Array<&#39;pkiElectronicfundstransferID_ASC&#39; &#124; &#39;pkiElectronicfundstransferID_DESC&#39; &#124; &#39;fkiPaymentmethodID_ASC&#39; &#124; &#39;fkiPaymentmethodID_DESC&#39; &#124; &#39;fkiUserIDCreated_ASC&#39; &#124; &#39;fkiUserIDCreated_DESC&#39; &#124; &#39;sPaymentmethodDescriptionX_ASC&#39; &#124; &#39;sPaymentmethodDescriptionX_DESC&#39; &#124; &#39;sUserLoginnameCreated_ASC&#39; &#124; &#39;sUserLoginnameCreated_DESC&#39; &#124; &#39;iElectronicfundstransferNumber_ASC&#39; &#124; &#39;iElectronicfundstransferNumber_DESC&#39; &#124; &#39;dtElectronicfundstransferDate_ASC&#39; &#124; &#39;dtElectronicfundstransferDate_DESC&#39; &#124; &#39;iElectronicfundstransferTransactioncount_ASC&#39; &#124; &#39;iElectronicfundstransferTransactioncount_DESC&#39; &#124; &#39;dElectronicfundstransferAmountvisible_ASC&#39; &#124; &#39;dElectronicfundstransferAmountvisible_DESC&#39;>** | Specify how you want the results to be sorted | (optional) defaults to undefined|
| **iRowMax** | [**number**] |  | (optional) defaults to undefined|
| **iRowOffset** | [**number**] |  | (optional) defaults to 0|
| **acceptLanguage** | **HeaderAcceptLanguage** |  | (optional) defaults to undefined|
| **sFilter** | [**string**] |  | (optional) defaults to undefined|


### Return type

**ElectronicfundstransferGetListV1Response**

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

# **electronicfundstransferImportIntoEDMV1**
> ElectronicfundstransferImportIntoEDMV1Response electronicfundstransferImportIntoEDMV1(electronicfundstransferImportIntoEDMV1Request)



### Example

```typescript
import {
    ObjectElectronicfundstransferApi,
    Configuration,
    ElectronicfundstransferImportIntoEDMV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectElectronicfundstransferApi(configuration);

let pkiElectronicfundstransferID: number; // (default to undefined)
let electronicfundstransferImportIntoEDMV1Request: ElectronicfundstransferImportIntoEDMV1Request; //

const { status, data } = await apiInstance.electronicfundstransferImportIntoEDMV1(
    pkiElectronicfundstransferID,
    electronicfundstransferImportIntoEDMV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **electronicfundstransferImportIntoEDMV1Request** | **ElectronicfundstransferImportIntoEDMV1Request**|  | |
| **pkiElectronicfundstransferID** | [**number**] |  | defaults to undefined|


### Return type

**ElectronicfundstransferImportIntoEDMV1Response**

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

