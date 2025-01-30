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


// May contain unused imports in some cases
// @ts-ignore
import type { FieldEUserEzsignsendreminderfrequency } from './field-euser-ezsignsendreminderfrequency';

/**
 * An Activesession->User Object and children to create a complete structure
 * @export
 * @interface ActivesessionResponseCompoundUser
 */
export interface ActivesessionResponseCompoundUser {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof ActivesessionResponseCompoundUser
     */
    /*'pkiUserID': number;*/
    'pkiUserID': number;
    /**
     * The unique ID of the Timezone
     * @type {number}
     * @memberof ActivesessionResponseCompoundUser
     */
    /*'fkiTimezoneID': number;*/
    'fkiTimezoneID': number;
    /**
     * The url of the picture used as avatar
     * @type {string}
     * @memberof ActivesessionResponseCompoundUser
     */
    /*'sAvatarUrl'?: string;*/
    'sAvatarUrl'?: string;
    /**
     * The first name of the user
     * @type {string}
     * @memberof ActivesessionResponseCompoundUser
     */
    /*'sUserFirstname': string;*/
    'sUserFirstname': string;
    /**
     * The last name of the user
     * @type {string}
     * @memberof ActivesessionResponseCompoundUser
     */
    /*'sUserLastname': string;*/
    'sUserLastname': string;
    /**
     * The email address.
     * @type {string}
     * @memberof ActivesessionResponseCompoundUser
     */
    /*'sEmailAddress'?: string;*/
    'sEmailAddress'?: string;
    /**
     * 
     * @type {FieldEUserEzsignsendreminderfrequency}
     * @memberof ActivesessionResponseCompoundUser
     */
    /*'eUserEzsignsendreminderfrequency': FieldEUserEzsignsendreminderfrequency;*/
    'eUserEzsignsendreminderfrequency': FieldEUserEzsignsendreminderfrequency;
    /**
     * The int32 representation of the interface color. For example, RGB color #39435B would be 3752795
     * @type {number}
     * @memberof ActivesessionResponseCompoundUser
     */
    /*'iUserInterfacecolor': number;*/
    'iUserInterfacecolor': number;
    /**
     * Whether to use a dark mode interface
     * @type {boolean}
     * @memberof ActivesessionResponseCompoundUser
     */
    /*'bUserInterfacedark': boolean;*/
    'bUserInterfacedark': boolean;
    /**
     * The number of rows to return by default in lists
     * @type {number}
     * @memberof ActivesessionResponseCompoundUser
     */
    /*'iUserListresult': number;*/
    'iUserListresult': number;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ActivesessionResponseCompoundUser Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectActivesessionResponseCompoundUser
 */
export class DataObjectActivesessionResponseCompoundUser {
   pkiUserID:number = 0
   fkiTimezoneID:number = 0
   sAvatarUrl?:string = undefined
   sUserFirstname:string = ''
   sUserLastname:string = ''
   sEmailAddress?:string = undefined
   eUserEzsignsendreminderfrequency:FieldEUserEzsignsendreminderfrequency = 'None'
   iUserInterfacecolor:number = 0
   bUserInterfacedark:boolean = false
   iUserListresult:number = 0
}

/**
 * @export 
 * A ActivesessionResponseCompoundUser Validation Object
 * @class ValidationObjectActivesessionResponseCompoundUser
 */
export class ValidationObjectActivesessionResponseCompoundUser {
   pkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiTimezoneID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sAvatarUrl = {
      type: 'string',
      pattern: /^(https|http):\/\/[^\s\/$.?#].[^\s]*$/,
      required: false
   }
   sUserFirstname = {
      type: 'string',
      required: true
   }
   sUserLastname = {
      type: 'string',
      required: true
   }
   sEmailAddress = {
      type: 'string',
      pattern: /^[\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/,
      required: false
   }
   eUserEzsignsendreminderfrequency = {
      type: 'enum',
      allowableValues: ['None','Daily','Weekly'],
      required: true
   }
   iUserInterfacecolor = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bUserInterfacedark = {
      type: 'boolean',
      required: true
   }
   iUserListresult = {
      type: 'integer',
      minimum: 5,
      maximum: 500,
      required: true
   }
} 


