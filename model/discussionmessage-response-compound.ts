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
import type { DiscussionmessageResponse } from './discussionmessage-response';
// May contain unused imports in some cases
// @ts-ignore
import type { FieldEDiscussionmessageStatus } from './field-ediscussionmessage-status';

/**
 * @type DiscussionmessageResponseCompound
 * A Discussionmessage Object and children
 * @export
 */
/*export type DiscussionmessageResponseCompound = DiscussionmessageResponse;*/
export interface DiscussionmessageResponseCompound {
    /**
     * The unique ID of the Discussionmessage
     * @type {number}
     * @memberof DiscussionmessageResponseCompound
     */
    pkiDiscussionmessageID:number 
    /**
     * The unique ID of the Discussion
     * @type {number}
     * @memberof DiscussionmessageResponseCompound
     */
    fkiDiscussionID:number 
    /**
     * The unique ID of the Discussionmembership
     * @type {number}
     * @memberof DiscussionmessageResponseCompound
     */
    fkiDiscussionmembershipID?:number 
    /**
     * The unique ID of the Discussionmembership
     * @type {number}
     * @memberof DiscussionmessageResponseCompound
     */
    fkiDiscussionmembershipIDActionrequired?:number 
    /**
     * 
     * @type {FieldEDiscussionmessageStatus}
     * @memberof DiscussionmessageResponseCompound
     */
    eDiscussionmessageStatus:FieldEDiscussionmessageStatus 
    /**
     * The content of the Discussionmessage
     * @type {string}
     * @memberof DiscussionmessageResponseCompound
     */
    tDiscussionmessageContent:string 
    /**
     * The name the creator of the Discussionmessage.
     * @type {string}
     * @memberof DiscussionmessageResponseCompound
     */
    sDiscussionmessageCreatorname:string 
    /**
     * The name the Actionrequired of the Discussionmessage.
     * @type {string}
     * @memberof DiscussionmessageResponseCompound
     */
    sDiscussionmessageActionrequiredname?:string 
    /**
     * 
     * @type {CommonAudit}
     * @memberof DiscussionmessageResponseCompound
     */
    objAudit:CommonAudit 
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
 * A DiscussionmessageResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectDiscussionmessageResponseCompound
 */
export class DataObjectDiscussionmessageResponseCompound {
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
 * A DiscussionmessageResponseCompound Validation Object
 * @class ValidationObjectDiscussionmessageResponseCompound
 */
export class ValidationObjectDiscussionmessageResponseCompound {
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
      pattern: /^.{0,65535}$/,
      required: true
   }
   sDiscussionmessageCreatorname = {
      type: 'string',
      pattern: /^.{0,75}$/,
      required: true
   }
   sDiscussionmessageActionrequiredname = {
      type: 'string',
      pattern: /^.{0,75}$/,
      required: false
   }
   objAudit = new ValidationObjectCommonAudit()
} 


