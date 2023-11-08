/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.2.0
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */



/**
 * Response for GET /1/ezmaxclient/{pksEzmaxclientOs}/version
 * @export
 * @interface GlobalEzmaxclientVersionV1Response
 */
export interface GlobalEzmaxclientVersionV1Response {
    /**
     * The version on the store
     * @type {string}
     * @memberof GlobalEzmaxclientVersionV1Response
     */
    'sEzmaxclientVersion': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A GlobalEzmaxclientVersionV1Response Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectGlobalEzmaxclientVersionV1Response
 */
export class DataObjectGlobalEzmaxclientVersionV1Response {
   sEzmaxclientVersion:string = ''
}

/**
 * @export 
 * A GlobalEzmaxclientVersionV1Response Validation Object
 * @class ValidationObjectGlobalEzmaxclientVersionV1Response
 */
export class ValidationObjectGlobalEzmaxclientVersionV1Response {
   sEzmaxclientVersion = {
      type: 'string',
      required: true
   }
} 

