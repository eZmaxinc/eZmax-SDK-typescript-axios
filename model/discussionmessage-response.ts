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


// May contain unused imports in some cases
// @ts-ignore
import { CommonAudit } from './common-audit';
// May contain unused imports in some cases
// @ts-ignore
import { FieldEDiscussionmessageStatus } from './field-ediscussionmessage-status';

/**
 * A Discussionmessage Object
 * @export
 * @interface DiscussionmessageResponse
 */
export interface DiscussionmessageResponse {
    /**
     * The unique ID of the Discussionmessage
     * @type {number}
     * @memberof DiscussionmessageResponse
     */
    /*'pkiDiscussionmessageID': number;*/
    'pkiDiscussionmessageID': number;
    /**
     * The unique ID of the Discussion
     * @type {number}
     * @memberof DiscussionmessageResponse
     */
    /*'fkiDiscussionID': number;*/
    'fkiDiscussionID': number;
    /**
     * The unique ID of the Discussionmembership
     * @type {number}
     * @memberof DiscussionmessageResponse
     */
    /*'fkiDiscussionmembershipID'?: number;*/
    'fkiDiscussionmembershipID'?: number;
    /**
     * The unique ID of the Discussionmembership
     * @type {number}
     * @memberof DiscussionmessageResponse
     */
    /*'fkiDiscussionmembershipIDActionrequired'?: number;*/
    'fkiDiscussionmembershipIDActionrequired'?: number;
    /**
     * 
     * @type {FieldEDiscussionmessageStatus}
     * @memberof DiscussionmessageResponse
     */
    /*'eDiscussionmessageStatus': FieldEDiscussionmessageStatus;*/
    'eDiscussionmessageStatus': FieldEDiscussionmessageStatus;
    /**
     * The content of the Discussionmessage
     * @type {string}
     * @memberof DiscussionmessageResponse
     */
    /*'tDiscussionmessageContent': string;*/
    'tDiscussionmessageContent': string;
    /**
     * The name the creator of the Discussionmessage.
     * @type {string}
     * @memberof DiscussionmessageResponse
     */
    /*'sDiscussionmessageCreatorname': string;*/
    'sDiscussionmessageCreatorname': string;
    /**
     * The name the Actionrequired of the Discussionmessage.
     * @type {string}
     * @memberof DiscussionmessageResponse
     */
    /*'sDiscussionmessageActionrequiredname'?: string;*/
    'sDiscussionmessageActionrequiredname'?: string;
    /**
     * 
     * @type {CommonAudit}
     * @memberof DiscussionmessageResponse
     */
    /*'objAudit': CommonAudit;*/
    'objAudit': CommonAudit;
}


/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonAudit } from './'
// @ts-ignore
import { ValidationObjectCommonAudit } from './'

/**
 * @export 
 * A DiscussionmessageResponse Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionmessageResponse
 */
export class DataObjectDiscussionmessageResponse {
   pkiDiscussionmessageID:number = 0
   fkiDiscussionID:number = 0
   fkiDiscussionmembershipID?:number = undefined
   fkiDiscussionmembershipIDActionrequired?:number = undefined
   eDiscussionmessageStatus:FieldEDiscussionmessageStatus = 'New'
   tDiscussionmessageContent:string = ''
   sDiscussionmessageCreatorname:string = ''
   sDiscussionmessageActionrequiredname?:string = undefined
   objAudit:CommonAudit = new DataObjectCommonAudit()
}

/**
 * @export 
 * A DiscussionmessageResponse Validation Object
 * @class ValidationObjectDiscussionmessageResponse
 */
export class ValidationObjectDiscussionmessageResponse {
   pkiDiscussionmessageID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   fkiDiscussionID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: true
   }
   fkiDiscussionmembershipID = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   fkiDiscussionmembershipIDActionrequired = {
      type: 'integer',
      minimum: 0,
      maximum: 16777215,
      required: false
   }
   eDiscussionmessageStatus = {
      type: 'enum',
      allowableValues: ['New','Edited','Deleted'],
      required: true
   }
   tDiscussionmessageContent = {
      type: 'string',
      pattern: '/^.{0,65535}$/',
      required: true
   }
   sDiscussionmessageCreatorname = {
      type: 'string',
      pattern: '/^.{0,75}$/',
      required: true
   }
   sDiscussionmessageActionrequiredname = {
      type: 'string',
      pattern: '/^.{0,75}$/',
      required: false
   }
   objAudit = new ValidationObjectCommonAudit()
} 

