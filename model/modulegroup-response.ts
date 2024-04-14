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
 * A Modulegroup Object
 * @export
 * @interface ModulegroupResponse
 */
export interface ModulegroupResponse {
    /**
     * The unique ID of the Modulegroup
     * @type {number}
     * @memberof ModulegroupResponse
     */
    /*'pkiModulegroupID': number;*/
    'pkiModulegroupID': number;
    /**
     * The name of the Modulegroup in the language of the requester
     * @type {string}
     * @memberof ModulegroupResponse
     */
    /*'sModulegroupNameX': string;*/
    'sModulegroupNameX': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ModulegroupResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectModulegroupResponse
 */
export class DataObjectModulegroupResponse {
   pkiModulegroupID:number = 0
   sModulegroupNameX:string = ''
}

/**
 * @export 
 * A ModulegroupResponse Validation Object
 * @class ValidationObjectModulegroupResponse
 */
export class ValidationObjectModulegroupResponse {
   pkiModulegroupID = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
   sModulegroupNameX = {
      type: 'string',
      pattern: '/^.{0,25}$/',
      required: true
   }
} 


