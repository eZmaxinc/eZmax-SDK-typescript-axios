/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.1
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import type { DiscussionRequestCompound } from './discussion-request-compound';

/**
 * Request for POST /1/object/discussion
 * @export
 * @interface DiscussionCreateObjectV1Request
 */
export interface DiscussionCreateObjectV1Request {
    /**
     * 
     * @type {Array<DiscussionRequestCompound>}
     * @memberof DiscussionCreateObjectV1Request
     */
    /*'a_objDiscussion': Array<DiscussionRequestCompound>;*/
    'a_objDiscussion': Array<DiscussionRequestCompound>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A DiscussionCreateObjectV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionCreateObjectV1Request
 */
export class DataObjectDiscussionCreateObjectV1Request {
   a_objDiscussion:Array<DiscussionRequestCompound> = []
}

/**
 * @export 
 * A DiscussionCreateObjectV1Request Validation Object
 * @class ValidationObjectDiscussionCreateObjectV1Request
 */
export class ValidationObjectDiscussionCreateObjectV1Request {
   a_objDiscussion = {
      type: 'array',
      minItems: 1,
      required: true
   }
} 


