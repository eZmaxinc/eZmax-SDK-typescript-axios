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



/**
 * An Activesession->Apikey object and children to create a complete structure
 * @export
 * @interface ActivesessionResponseCompoundApikey
 */
export interface ActivesessionResponseCompoundApikey {
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof ActivesessionResponseCompoundApikey
     */
    /*'pkiApikeyID': number;*/
    'pkiApikeyID': number;
    /**
     * The description of the Apikey in the language of the requester
     * @type {string}
     * @memberof ActivesessionResponseCompoundApikey
     */
    /*'sApikeyDescriptionX': string;*/
    'sApikeyDescriptionX': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ActivesessionResponseCompoundApikey Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectActivesessionResponseCompoundApikey
 */
export class DataObjectActivesessionResponseCompoundApikey {
   pkiApikeyID:number = 0
   sApikeyDescriptionX:string = ''
}

/**
 * @export 
 * A ActivesessionResponseCompoundApikey Validation Object
 * @class ValidationObjectActivesessionResponseCompoundApikey
 */
export class ValidationObjectActivesessionResponseCompoundApikey {
   pkiApikeyID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sApikeyDescriptionX = {
      type: 'string',
      required: true
   }
} 


