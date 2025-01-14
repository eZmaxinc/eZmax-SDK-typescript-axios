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
import { FieldESessionhistoryEndby } from './field-esessionhistory-endby';

/**
 * A Sessionhistory List Element
 * @export
 * @interface SessionhistoryListElement
 */
export interface SessionhistoryListElement {
    /**
     * The unique ID of the Sessionhistory
     * @type {number}
     * @memberof SessionhistoryListElement
     */
    /*'pkiSessionhistoryID': number;*/
    'pkiSessionhistoryID': number;
    /**
     * The unique ID of the Computer
     * @type {number}
     * @memberof SessionhistoryListElement
     */
    /*'fkiComputerID'?: number;*/
    'fkiComputerID'?: number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof SessionhistoryListElement
     */
    /*'fkiUserID'?: number;*/
    'fkiUserID'?: number;
    /**
     * The first hit of the Sessionhistory
     * @type {string}
     * @memberof SessionhistoryListElement
     */
    /*'dtSessionhistoryFirsthit': string;*/
    'dtSessionhistoryFirsthit': string;
    /**
     * The last hit of the Sessionhistory
     * @type {string}
     * @memberof SessionhistoryListElement
     */
    /*'dtSessionhistoryLasthit': string;*/
    'dtSessionhistoryLasthit': string;
    /**
     * 
     * @type {FieldESessionhistoryEndby}
     * @memberof SessionhistoryListElement
     */
    /*'eSessionhistoryEndby': FieldESessionhistoryEndby;*/
    'eSessionhistoryEndby': FieldESessionhistoryEndby;
    /**
     * The description of the Computer
     * @type {string}
     * @memberof SessionhistoryListElement
     */
    /*'sComputerDescription'?: string;*/
    'sComputerDescription'?: string;
    /**
     * The duration of the session
     * @type {string}
     * @memberof SessionhistoryListElement
     */
    /*'sSessionhistoryDuration': string;*/
    'sSessionhistoryDuration': string;
    /**
     * Represent an IP address.
     * @type {string}
     * @memberof SessionhistoryListElement
     */
    /*'sSessionhistoryIP': string;*/
    'sSessionhistoryIP': string;
    /**
     * The login name of the User.
     * @type {string}
     * @memberof SessionhistoryListElement
     */
    /*'sUserLoginname'?: string;*/
    'sUserLoginname'?: string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A SessionhistoryListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectSessionhistoryListElement
 */
export class DataObjectSessionhistoryListElement {
   pkiSessionhistoryID:number = 0
   fkiComputerID?:number = undefined
   fkiUserID?:number = undefined
   dtSessionhistoryFirsthit:string = ''
   dtSessionhistoryLasthit:string = ''
   eSessionhistoryEndby:FieldESessionhistoryEndby = 'Decryption'
   sComputerDescription?:string = undefined
   sSessionhistoryDuration:string = ''
   sSessionhistoryIP:string = ''
   sUserLoginname?:string = undefined
}

/**
 * @export 
 * A SessionhistoryListElement Validation Object
 * @class ValidationObjectSessionhistoryListElement
 */
export class ValidationObjectSessionhistoryListElement {
   pkiSessionhistoryID = {
      type: 'integer',
      minimum: 1,
      maximum: 2147483647,
      required: true
   }
   fkiComputerID = {
      type: 'integer',
      minimum: 1,
      maximum: 65535,
      required: false
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: false
   }
   dtSessionhistoryFirsthit = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
   dtSessionhistoryLasthit = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
   eSessionhistoryEndby = {
      type: 'enum',
      allowableValues: ['Decryption','Hack','Expired','Hijack','DoubleLogon','Garbage','Logoff','BadAuth','Locked','Inactive','InvalidUser','BadUserType','BadIP','ForcedLogoff'],
      required: true
   }
   sComputerDescription = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
   sSessionhistoryDuration = {
      type: 'string',
      pattern: /^(0[0-9]{1}|\d{2,}):([0-5][0-9]):([0-5][0-9])$/,
      required: true
   }
   sSessionhistoryIP = {
      type: 'string',
      required: true
   }
   sUserLoginname = {
      type: 'string',
      pattern: /^(?:([\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20})|([a-zA-Z0-9]){1,32})$/,
      required: false
   }
} 


