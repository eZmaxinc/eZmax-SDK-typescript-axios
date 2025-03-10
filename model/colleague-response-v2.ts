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
import type { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import type { CustomUserNameResponse } from './custom-user-name-response';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEColleagueEzsign } from './field-ecolleague-ezsign';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEColleagueRealestateinprogess } from './field-ecolleague-realestateinprogess';

/**
 * A Colleague Object
 * @export
 * @interface ColleagueResponseV2
 */
export interface ColleagueResponseV2 {
    /**
     * The unique ID of the Colleague
     * @type {number}
     * @memberof ColleagueResponseV2
     */
    /*'pkiColleagueID': number;*/
    'pkiColleagueID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof ColleagueResponseV2
     */
    /*'fkiUserID': number;*/
    'fkiUserID': number;
    /**
     * The unique ID of the User
     * @type {number}
     * @memberof ColleagueResponseV2
     */
    /*'fkiUserIDColleague': number;*/
    'fkiUserIDColleague': number;
    /**
     * Whether the email can be used by the cloning user in Ezsign
     * @type {boolean}
     * @memberof ColleagueResponseV2
     */
    /*'bColleagueEzsignemail': boolean;*/
    'bColleagueEzsignemail': boolean;
    /**
     * Whether the cloning user has access to the financial
     * @type {boolean}
     * @memberof ColleagueResponseV2
     */
    /*'bColleagueFinancial': boolean;*/
    'bColleagueFinancial': boolean;
    /**
     * Whether the cloning user has access to the cloned user email to send communications
     * @type {boolean}
     * @memberof ColleagueResponseV2
     */
    /*'bColleagueUsecloneemail': boolean;*/
    'bColleagueUsecloneemail': boolean;
    /**
     * Whether the cloning user has access to the attachment
     * @type {boolean}
     * @memberof ColleagueResponseV2
     */
    /*'bColleagueAttachment': boolean;*/
    'bColleagueAttachment': boolean;
    /**
     * Whether the cloning user has access to canafe
     * @type {boolean}
     * @memberof ColleagueResponseV2
     */
    /*'bColleagueCanafe': boolean;*/
    'bColleagueCanafe': boolean;
    /**
     * Whether the cloning user copies the permission of the cloned user
     * @type {boolean}
     * @memberof ColleagueResponseV2
     */
    /*'bColleaguePermission': boolean;*/
    'bColleaguePermission': boolean;
    /**
     * Whether if the cloning user has access to the completed folders in real estate
     * @type {boolean}
     * @memberof ColleagueResponseV2
     */
    /*'bColleagueRealestatecompleted': boolean;*/
    'bColleagueRealestatecompleted': boolean;
    /**
     * The from of the Colleague
     * @type {string}
     * @memberof ColleagueResponseV2
     */
    /*'dtColleagueFrom'?: string;*/
    'dtColleagueFrom'?: string;
    /**
     * The to of the Colleague
     * @type {string}
     * @memberof ColleagueResponseV2
     */
    /*'dtColleagueTo'?: string;*/
    'dtColleagueTo'?: string;
    /**
     * 
     * @type {FieldEColleagueEzsign}
     * @memberof ColleagueResponseV2
     */
    /*'eColleagueEzsign': FieldEColleagueEzsign;*/
    'eColleagueEzsign': FieldEColleagueEzsign;
    /**
     * 
     * @type {FieldEColleagueRealestateinprogess}
     * @memberof ColleagueResponseV2
     */
    /*'eColleagueRealestateinprogress': FieldEColleagueRealestateinprogess;*/
    'eColleagueRealestateinprogress': FieldEColleagueRealestateinprogess;
    /**
     * 
     * @type {CustomUserNameResponse}
     * @memberof ColleagueResponseV2
     */
    /*'objUserName': CustomUserNameResponse;*/
    'objUserName': CustomUserNameResponse;
    /**
     * 
     * @type {CommonAudit}
     * @memberof ColleagueResponseV2
     */
    /*'objAudit': CommonAudit;*/
    'objAudit': CommonAudit;
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCustomUserNameResponse } from './'
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCustomUserNameResponse } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A ColleagueResponseV2 Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectColleagueResponseV2
 */
export class DataObjectColleagueResponseV2 {
   pkiColleagueID:number = 0
   fkiUserID:number = 0
   fkiUserIDColleague:number = 0
   bColleagueEzsignemail:boolean = false
   bColleagueFinancial:boolean = false
   bColleagueUsecloneemail:boolean = false
   bColleagueAttachment:boolean = false
   bColleagueCanafe:boolean = false
   bColleaguePermission:boolean = false
   bColleagueRealestatecompleted:boolean = false
   dtColleagueFrom?:string = undefined
   dtColleagueTo?:string = undefined
   eColleagueEzsign:FieldEColleagueEzsign = 'No'
   eColleagueRealestateinprogress:FieldEColleagueRealestateinprogess = 'No'
   objUserName:CustomUserNameResponse = new DataObjectCustomUserNameResponse()
   objAudit:CommonAudit = new DataObjectCommonAudit()
}

/**
 * @export 
 * A ColleagueResponseV2 Validation Object
 * @class ValidationObjectColleagueResponseV2
 */
export class ValidationObjectColleagueResponseV2 {
   pkiColleagueID = {
      type: 'integer',
      minimum: 0,
      maximum: 65535,
      required: true
   }
   fkiUserID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiUserIDColleague = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   bColleagueEzsignemail = {
      type: 'boolean',
      required: true
   }
   bColleagueFinancial = {
      type: 'boolean',
      required: true
   }
   bColleagueUsecloneemail = {
      type: 'boolean',
      required: true
   }
   bColleagueAttachment = {
      type: 'boolean',
      required: true
   }
   bColleagueCanafe = {
      type: 'boolean',
      required: true
   }
   bColleaguePermission = {
      type: 'boolean',
      required: true
   }
   bColleagueRealestatecompleted = {
      type: 'boolean',
      required: true
   }
   dtColleagueFrom = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/,
      required: false
   }
   dtColleagueTo = {
      type: 'string',
      pattern: /^[0-9]{4}-(0[1-9]|1[0-2])-(0[1-9]|[1-2][0-9]|3[0-1])$/,
      required: false
   }
   eColleagueEzsign = {
      type: 'enum',
      allowableValues: ['No','Read','Modify','Full'],
      required: true
   }
   eColleagueRealestateinprogress = {
      type: 'enum',
      allowableValues: ['No','Read','Modify','Create'],
      required: true
   }
   objUserName = new ValidationObjectCustomUserNameResponse()
   objAudit = new ValidationObjectCommonAudit()
} 


