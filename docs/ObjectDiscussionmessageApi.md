# ObjectDiscussionmessageApi

All URIs are relative to *https://prod.api.appcluster01.ca-central-1.ezmax.com/rest*

|Method | HTTP request | Description|
|------------- | ------------- | -------------|
|[**discussionmessageCreateObjectV1**](#discussionmessagecreateobjectv1) | **POST** /1/object/discussionmessage | Create a new Discussionmessage|
|[**discussionmessageDeleteObjectV1**](#discussionmessagedeleteobjectv1) | **DELETE** /1/object/discussionmessage/{pkiDiscussionmessageID} | Delete an existing Discussionmessage|
|[**discussionmessagePatchObjectV1**](#discussionmessagepatchobjectv1) | **PATCH** /1/object/discussionmessage/{pkiDiscussionmessageID} | Patch an existing Discussionmessage|

# **discussionmessageCreateObjectV1**
> DiscussionmessageCreateObjectV1Response discussionmessageCreateObjectV1(discussionmessageCreateObjectV1Request)

The endpoint allows to create one or many elements at once.

### Example

```typescript
import {
    ObjectDiscussionmessageApi,
    Configuration,
    DiscussionmessageCreateObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDiscussionmessageApi(configuration);

let discussionmessageCreateObjectV1Request: DiscussionmessageCreateObjectV1Request; //

const { status, data } = await apiInstance.discussionmessageCreateObjectV1(
    discussionmessageCreateObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **discussionmessageCreateObjectV1Request** | **DiscussionmessageCreateObjectV1Request**|  | |


### Return type

**DiscussionmessageCreateObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**201** | Successful response |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **discussionmessageDeleteObjectV1**
> DiscussionmessageDeleteObjectV1Response discussionmessageDeleteObjectV1()



### Example

```typescript
import {
    ObjectDiscussionmessageApi,
    Configuration
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDiscussionmessageApi(configuration);

let pkiDiscussionmessageID: number; //The unique ID of the Discussionmessage (default to undefined)

const { status, data } = await apiInstance.discussionmessageDeleteObjectV1(
    pkiDiscussionmessageID
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **pkiDiscussionmessageID** | [**number**] | The unique ID of the Discussionmessage | defaults to undefined|


### Return type

**DiscussionmessageDeleteObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: Not defined
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

# **discussionmessagePatchObjectV1**
> DiscussionmessagePatchObjectV1Response discussionmessagePatchObjectV1(discussionmessagePatchObjectV1Request)



### Example

```typescript
import {
    ObjectDiscussionmessageApi,
    Configuration,
    DiscussionmessagePatchObjectV1Request
} from '@ezmaxinc/ezmax-sdk-typescript-axios';

const configuration = new Configuration();
const apiInstance = new ObjectDiscussionmessageApi(configuration);

let pkiDiscussionmessageID: number; //The unique ID of the Discussionmessage (default to undefined)
let discussionmessagePatchObjectV1Request: DiscussionmessagePatchObjectV1Request; //

const { status, data } = await apiInstance.discussionmessagePatchObjectV1(
    pkiDiscussionmessageID,
    discussionmessagePatchObjectV1Request
);
```

### Parameters

|Name | Type | Description  | Notes|
|------------- | ------------- | ------------- | -------------|
| **discussionmessagePatchObjectV1Request** | **DiscussionmessagePatchObjectV1Request**|  | |
| **pkiDiscussionmessageID** | [**number**] | The unique ID of the Discussionmessage | defaults to undefined|


### Return type

**DiscussionmessagePatchObjectV1Response**

### Authorization

[Authorization](../README.md#Authorization)

### HTTP request headers

 - **Content-Type**: application/json
 - **Accept**: application/json


### HTTP response details
| Status code | Description | Response headers |
|-------------|-------------|------------------|
|**200** | Successful response |  -  |
|**404** | The request failed. The element on which you were trying to work does not exists. Look for detail about the error in the body |  -  |
|**422** | The request was syntactically valid but failed because of an interdependance condition. Look for detail about the error in the body |  -  |

[[Back to top]](#) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to Model list]](../README.md#documentation-for-models) [[Back to README]](../README.md)

