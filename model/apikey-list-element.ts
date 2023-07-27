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



/**
 * A Branding List Element
 * @export
 * @interface ApikeyListElement
 */
export interface ApikeyListElement {
    /**
     * The unique ID of the Apikey
     * @type {number}
     * @memberof ApikeyListElement
     */
    'pkiApikeyID': number;
    /**
     * The description of the Apikey in the language of the requester
     * @type {string}
     * @memberof ApikeyListElement
     */
    'sApikeyDescriptionX': string;
    /**
     * The first name of the user
     * @type {string}
     * @memberof ApikeyListElement
     */
    'sUserFirstname': string;
    /**
     * The last name of the user
     * @type {string}
     * @memberof ApikeyListElement
     */
    'sUserLastname': string;
    /**
     * Whether the apikey is active or not
     * @type {boolean}
     * @memberof ApikeyListElement
     */
    'bApikeyIsactive': boolean;
    /**
     * Whether the apikey is signed or not
     * @type {boolean}
     * @memberof ApikeyListElement
     */
    'bApikeyIssigned': boolean;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ApikeyListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectApikeyListElement
 */
export class DataObjectApikeyListElement {
   pkiApikeyID:number = 0
   sApikeyDescriptionX:string = ''
   sUserFirstname:string = ''
   sUserLastname:string = ''
   bApikeyIsactive:boolean = false
   bApikeyIssigned:boolean = false
}

/**
 * @export 
 * A ApikeyListElement Validation Object
 * @class ValidationObjectApikeyListElement
 */
export class ValidationObjectApikeyListElement {
   pkiApikeyID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sApikeyDescriptionX = {
      type: 'string',
      required: true
   }
   sUserFirstname = {
      type: 'string',
      required: true
   }
   sUserLastname = {
      type: 'string',
      required: true
   }
   bApikeyIsactive = {
      type: 'boolean',
      required: true
   }
   bApikeyIssigned = {
      type: 'boolean',
      required: true
   }
} 


