/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.18
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CustomCommunicationListElementResponse } from './custom-communication-list-element-response';

/**
 * 
 * @export
 * @interface EzsignfolderGetCommunicationListV1ResponseMPayloadAllOf
 */
export interface EzsignfolderGetCommunicationListV1ResponseMPayloadAllOf {
    /**
     * 
     * @type {Array<CustomCommunicationListElementResponse>}
     * @memberof EzsignfolderGetCommunicationListV1ResponseMPayloadAllOf
     */
    'a_objCommunication': Array<CustomCommunicationListElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderGetCommunicationListV1ResponseMPayloadAllOf Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetCommunicationListV1ResponseMPayloadAllOf
 */
export class DataObjectEzsignfolderGetCommunicationListV1ResponseMPayloadAllOf {
   a_objCommunication:Array<CustomCommunicationListElementResponse> = []
}

/**
 * @export 
 * A EzsignfolderGetCommunicationListV1ResponseMPayloadAllOf Validation Object
 * @class ValidationObjectEzsignfolderGetCommunicationListV1ResponseMPayloadAllOf
 */
export class ValidationObjectEzsignfolderGetCommunicationListV1ResponseMPayloadAllOf {
   a_objCommunication = {
      type: 'array',
      required: true
   }
} 


