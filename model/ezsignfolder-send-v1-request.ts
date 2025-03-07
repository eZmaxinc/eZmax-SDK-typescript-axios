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



/**
 * Request for POST /1/object/ezsignfolder/{pkiEzsignfolderID}/send
 * @export
 * @interface EzsignfolderSendV1Request
 */
export interface EzsignfolderSendV1Request {
    /**
     * A custom text message that will be added to the email sent.
     * @type {string}
     * @memberof EzsignfolderSendV1Request
     */
    /*'tExtraMessage': string;*/
    'tExtraMessage': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A EzsignfolderSendV1Request Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectEzsignfolderSendV1Request
 */
export class DataObjectEzsignfolderSendV1Request {
   tExtraMessage:string = ''
}

/**
 * @export 
 * A EzsignfolderSendV1Request Validation Object
 * @class ValidationObjectEzsignfolderSendV1Request
 */
export class ValidationObjectEzsignfolderSendV1Request {
   tExtraMessage = {
      type: 'string',
      required: true
   }
} 


