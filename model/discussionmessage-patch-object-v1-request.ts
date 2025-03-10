/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.2
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { DiscussionmessageRequestPatch } from './discussionmessage-request-patch';

/**
 * Request for PATCH /1/object/discussionmessage/{pkiDiscussionmessageID}
 * @export
 * @interface DiscussionmessagePatchObjectV1Request
 */
export interface DiscussionmessagePatchObjectV1Request {
    /**
     * 
     * @type {DiscussionmessageRequestPatch}
     * @memberof DiscussionmessagePatchObjectV1Request
     */
    /*'objDiscussionmessage': DiscussionmessageRequestPatch;*/
    'objDiscussionmessage': DiscussionmessageRequestPatch;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectDiscussionmessageRequestPatch } from './'
// @ts-ignore
import { ValidationObjectDiscussionmessageRequestPatch } from './'

/**
 * @export 
 * A DiscussionmessagePatchObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionmessagePatchObjectV1Request
 */
export class DataObjectDiscussionmessagePatchObjectV1Request {
   objDiscussionmessage:DiscussionmessageRequestPatch = new DataObjectDiscussionmessageRequestPatch()
}

/**
 * @export 
 * A DiscussionmessagePatchObjectV1Request Validation Object
 * @class ValidationObjectDiscussionmessagePatchObjectV1Request
 */
export class ValidationObjectDiscussionmessagePatchObjectV1Request {
   objDiscussionmessage = new ValidationObjectDiscussionmessageRequestPatch()
} 


