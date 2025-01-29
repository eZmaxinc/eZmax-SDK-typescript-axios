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
import type { CustomCommunicationListElementResponse } from './custom-communication-list-element-response';

/**
 * Response for GET /1/object/ezsignfolder/{pkiEzsignfolderID}/getCommunicationList
 * @export
 * @interface EzsignfolderGetCommunicationListV1ResponseMPayload
 */
export interface EzsignfolderGetCommunicationListV1ResponseMPayload {
    /**
     * 
     * @type {Array<CustomCommunicationListElementResponse>}
     * @memberof EzsignfolderGetCommunicationListV1ResponseMPayload
     */
    /*'a_objCommunication': Array<CustomCommunicationListElementResponse>;*/
    'a_objCommunication': Array<CustomCommunicationListElementResponse>;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderGetCommunicationListV1ResponseMPayload Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderGetCommunicationListV1ResponseMPayload
 */
export class DataObjectEzsignfolderGetCommunicationListV1ResponseMPayload {
   a_objCommunication:Array<CustomCommunicationListElementResponse> = []
}

/**
 * @export 
 * A EzsignfolderGetCommunicationListV1ResponseMPayload Validation Object
 * @class ValidationObjectEzsignfolderGetCommunicationListV1ResponseMPayload
 */
export class ValidationObjectEzsignfolderGetCommunicationListV1ResponseMPayload {
   a_objCommunication = {
      type: 'array',
      required: true
   }
} 


