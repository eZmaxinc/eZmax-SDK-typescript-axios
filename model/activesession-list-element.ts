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
 * A Activesession List Element
 * @export
 * @interface ActivesessionListElement
 */
export interface ActivesessionListElement {
    /**
     * The unique ID of the Activesession
     * @type {number}
     * @memberof ActivesessionListElement
     */
    /*'pkiActivesessionID': number;*/
    'pkiActivesessionID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof ActivesessionListElement
     */
    /*'fkiUserID': number;*/
    'fkiUserID': number;
    /**
     * The unique ID of the Computer
     * @type {number}
     * @memberof ActivesessionListElement
     */
    /*'fkiComputerID': number;*/
    'fkiComputerID': number;
    /**
     * The unique ID of the Company
     * @type {number}
     * @memberof ActivesessionListElement
     */
    /*'fkiCompanyID': number;*/
    'fkiCompanyID': number;
    /**
     * The unique ID of the Department
     * @type {number}
     * @memberof ActivesessionListElement
     */
    /*'fkiDepartmentID': number;*/
    'fkiDepartmentID': number;
    /**
     * The Name of the Company in the language of the requester
     * @type {string}
     * @memberof ActivesessionListElement
     */
    /*'sCompanyNameX': string;*/
    'sCompanyNameX': string;
    /**
     * The Name of the Department in the language of the requester
     * @type {string}
     * @memberof ActivesessionListElement
     */
    /*'sDepartmentNameX': string;*/
    'sDepartmentNameX': string;
    /**
     * The loginname of the Activesession
     * @type {string}
     * @memberof ActivesessionListElement
     */
    /*'sActivesessionLoginname': string;*/
    'sActivesessionLoginname': string;
    /**
     * The description of the Computer
     * @type {string}
     * @memberof ActivesessionListElement
     */
    /*'sComputerDescription': string;*/
    'sComputerDescription': string;
    /**
     * The first hit of the Activesession
     * @type {string}
     * @memberof ActivesessionListElement
     */
    /*'dtActivesessionFirsthit': string;*/
    'dtActivesessionFirsthit': string;
    /**
     * The last hit of the Activesession
     * @type {string}
     * @memberof ActivesessionListElement
     */
    /*'dtActivesessionLasthit': string;*/
    'dtActivesessionLasthit': string;
    /**
     * Represent an IP address.
     * @type {string}
     * @memberof ActivesessionListElement
     */
    /*'sActivesessionIP': string;*/
    'sActivesessionIP': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ActivesessionListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectActivesessionListElement
 */
export class DataObjectActivesessionListElement {
   pkiActivesessionID:number = 0
   fkiUserID:number = 0
   fkiComputerID:number = 0
   fkiCompanyID:number = 0
   fkiDepartmentID:number = 0
   sCompanyNameX:string = ''
   sDepartmentNameX:string = ''
   sActivesessionLoginname:string = ''
   sComputerDescription:string = ''
   dtActivesessionFirsthit:string = ''
   dtActivesessionLasthit:string = ''
   sActivesessionIP:string = ''
}

/**
 * @export 
 * A ActivesessionListElement Validation Object
 * @class ValidationObjectActivesessionListElement
 */
export class ValidationObjectActivesessionListElement {
   pkiActivesessionID = {
      type: 'integer',
      required: true
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiComputerID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: true
   }
   fkiCompanyID = {
      type: 'integer',
      minimum: 1,
      maximum: 255,
      required: true
   }
   fkiDepartmentID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sCompanyNameX = {
      type: 'string',
      required: true
   }
   sDepartmentNameX = {
      type: 'string',
      required: true
   }
   sActivesessionLoginname = {
      type: 'string',
      pattern: /^.{0,32}$/,
      required: true
   }
   sComputerDescription = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: true
   }
   dtActivesessionFirsthit = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
   dtActivesessionLasthit = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
   sActivesessionIP = {
      type: 'string',
      required: true
   }
} 


