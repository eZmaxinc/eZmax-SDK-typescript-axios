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
 * Detail of the Versionhistory
 * @export
 * @interface MultilingualVersionhistoryDetail
 */
export interface MultilingualVersionhistoryDetail {
    /**
     * Detail of the Versionhistory in French
     * @type {string}
     * @memberof MultilingualVersionhistoryDetail
     */
    /*'tVersionhistoryDetail1'?: string;*/
    'tVersionhistoryDetail1'?: string;
    /**
     * Detail of the Versionhistory in English
     * @type {string}
     * @memberof MultilingualVersionhistoryDetail
     */
    /*'tVersionhistoryDetail2'?: string;*/
    'tVersionhistoryDetail2'?: string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A MultilingualVersionhistoryDetail Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectMultilingualVersionhistoryDetail
 */
export class DataObjectMultilingualVersionhistoryDetail {
   tVersionhistoryDetail1?:string = undefined
   tVersionhistoryDetail2?:string = undefined
}

/**
 * @export 
 * A MultilingualVersionhistoryDetail Validation Object
 * @class ValidationObjectMultilingualVersionhistoryDetail
 */
export class ValidationObjectMultilingualVersionhistoryDetail {
   tVersionhistoryDetail1 = {
      type: 'string',
      required: false
   }
   tVersionhistoryDetail2 = {
      type: 'string',
      required: false
   }
} 


