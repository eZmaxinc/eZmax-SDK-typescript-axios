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
import type { FieldEUserEzsignaccess } from './field-euser-ezsignaccess';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEUserOrigin } from './field-euser-origin';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEUserType } from './field-euser-type';

/**
 * A User List Element
 * @export
 * @interface UserListElement
 */
export interface UserListElement {
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof UserListElement
     */
    /*'pkiUserID': number;*/
    'pkiUserID': number;
    /**
     * The first name of the user
     * @type {string}
     * @memberof UserListElement
     */
    /*'sUserFirstname': string;*/
    'sUserFirstname': string;
    /**
     * The last name of the user
     * @type {string}
     * @memberof UserListElement
     */
    /*'sUserLastname': string;*/
    'sUserLastname': string;
    /**
     * The login name of the User.
     * @type {string}
     * @memberof UserListElement
     */
    /*'sUserLoginname': string;*/
    'sUserLoginname': string;
    /**
     * Whether the User is active or not
     * @type {boolean}
     * @memberof UserListElement
     */
    /*'bUserIsactive': boolean;*/
    'bUserIsactive': boolean;
    /**
     * 
     * @type {FieldEUserType}
     * @memberof UserListElement
     */
    /*'eUserType': FieldEUserType;*/
    'eUserType': FieldEUserType;
    /**
     * 
     * @type {FieldEUserOrigin}
     * @memberof UserListElement
     */
    /*'eUserOrigin': FieldEUserOrigin;*/
    'eUserOrigin': FieldEUserOrigin;
    /**
     * 
     * @type {FieldEUserEzsignaccess}
     * @memberof UserListElement
     */
    /*'eUserEzsignaccess': FieldEUserEzsignaccess;*/
    'eUserEzsignaccess': FieldEUserEzsignaccess;
    /**
     * The eZsign prepaid expiration date
     * @type {string}
     * @memberof UserListElement
     */
    /*'dtUserEzsignprepaidexpiration'?: string;*/
    'dtUserEzsignprepaidexpiration'?: string;
    /**
     * The email address.
     * @type {string}
     * @memberof UserListElement
     */
    /*'sEmailAddress': string;*/
    'sEmailAddress': string;
    /**
     * The job title of the user
     * @type {string}
     * @memberof UserListElement
     */
    /*'sUserJobtitle'?: string;*/
    'sUserJobtitle'?: string;
}


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A UserListElement Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectUserListElement
 */
export class DataObjectUserListElement {
   pkiUserID:number = 0
   sUserFirstname:string = ''
   sUserLastname:string = ''
   sUserLoginname:string = ''
   bUserIsactive:boolean = false
   eUserType:FieldEUserType = 'AgentBroker'
   eUserOrigin:FieldEUserOrigin = 'BuiltIn'
   eUserEzsignaccess:FieldEUserEzsignaccess = 'No'
   dtUserEzsignprepaidexpiration?:string = undefined
   sEmailAddress:string = ''
   sUserJobtitle?:string = undefined
}

/**
 * @export 
 * A UserListElement Validation Object
 * @class ValidationObjectUserListElement
 */
export class ValidationObjectUserListElement {
   pkiUserID = {
      type: 'integer',
      minimum: 0,
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
   sUserLoginname = {
      type: 'string',
      pattern: /^(?:([\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20})|([a-zA-Z0-9]){1,32})$/,
      required: true
   }
   bUserIsactive = {
      type: 'boolean',
      required: true
   }
   eUserType = {
      type: 'enum',
      allowableValues: ['AgentBroker','Assistant','Employee','EzsignUser','Normal'],
      required: true
   }
   eUserOrigin = {
      type: 'enum',
      allowableValues: ['BuiltIn','External'],
      required: true
   }
   eUserEzsignaccess = {
      type: 'enum',
      allowableValues: ['No','PaidByOffice','PerDocument','Prepaid'],
      required: true
   }
   dtUserEzsignprepaidexpiration = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/,
      required: false
   }
   sEmailAddress = {
      type: 'string',
      pattern: /^[\w.%+\-!#$%&'*+\/=?^`{|}~]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,20}$/,
      required: true
   }
   sUserJobtitle = {
      type: 'string',
      pattern: /^.{0,50}$/,
      required: false
   }
} 


