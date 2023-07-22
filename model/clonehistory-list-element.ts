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
 * A Clonehistory List Element
 * @export
 * @interface ClonehistoryListElement
 */
export interface ClonehistoryListElement {
    /**
     * The unique ID of the Clonehistory
     * @type {number}
     * @memberof ClonehistoryListElement
     */
    'pkiClonehistoryID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof ClonehistoryListElement
     */
    'fkiUserIDCloning': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof ClonehistoryListElement
     */
    'fkiUserIDCloned': number;
    /**
     * The firsthit of the Clonehistory
     * @type {string}
     * @memberof ClonehistoryListElement
     */
    'dtClonehistoryFirsthit': string;
    /**
     * The lasthit of the Clonehistory
     * @type {string}
     * @memberof ClonehistoryListElement
     */
    'dtClonehistoryLasthit'?: string;
    /**
     * The login name of the User.
     * @type {string}
     * @memberof ClonehistoryListElement
     */
    'sUserLoginnameCloning': string;
    /**
     * The first name of the user
     * @type {string}
     * @memberof ClonehistoryListElement
     */
    'sUserFirstnameCloning': string;
    /**
     * The last name of the user
     * @type {string}
     * @memberof ClonehistoryListElement
     */
    'sUserLastnameCloning': string;
    /**
     * The login name of the User.
     * @type {string}
     * @memberof ClonehistoryListElement
     */
    'sUserLoginnameCloned': string;
    /**
     * The first name of the user
     * @type {string}
     * @memberof ClonehistoryListElement
     */
    'sUserFirstnameCloned': string;
    /**
     * The last name of the user
     * @type {string}
     * @memberof ClonehistoryListElement
     */
    'sUserLastnameCloned': string;
}
/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ClonehistoryListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectClonehistoryListElement
 */
export class DataObjectClonehistoryListElement {
   pkiClonehistoryID:number = 0
   fkiUserIDCloning:number = 0
   fkiUserIDCloned:number = 0
   dtClonehistoryFirsthit:string = ''
   dtClonehistoryLasthit?:string = undefined
   sUserLoginnameCloning:string = ''
   sUserFirstnameCloning:string = ''
   sUserLastnameCloning:string = ''
   sUserLoginnameCloned:string = ''
   sUserFirstnameCloned:string = ''
   sUserLastnameCloned:string = ''
}

/**
 * @export 
 * A ClonehistoryListElement Validation Object
 * @class ValidationObjectClonehistoryListElement
 */
export class ValidationObjectClonehistoryListElement {
   pkiClonehistoryID = {
      type: 'integer',
      minimum: 1,
      maximum: 16777215,
      required: true
   }
   fkiUserIDCloning = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiUserIDCloned = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   dtClonehistoryFirsthit = {
      type: 'string',
      pattern: '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/',
      required: true
   }
   dtClonehistoryLasthit = {
      type: 'string',
      pattern: '/^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1]) ([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$/',
      required: false
   }
   sUserLoginnameCloning = {
      type: 'string',
      pattern: '/^(?:([\w\.-]+@[\w\.-]+\.\w{2,4})|([a-zA-Z0-9]){1,32})$/',
      required: true
   }
   sUserFirstnameCloning = {
      type: 'string',
      required: true
   }
   sUserLastnameCloning = {
      type: 'string',
      required: true
   }
   sUserLoginnameCloned = {
      type: 'string',
      pattern: '/^(?:([\w\.-]+@[\w\.-]+\.\w{2,4})|([a-zA-Z0-9]){1,32})$/',
      required: true
   }
   sUserFirstnameCloned = {
      type: 'string',
      required: true
   }
   sUserLastnameCloned = {
      type: 'string',
      required: true
   }
} 


