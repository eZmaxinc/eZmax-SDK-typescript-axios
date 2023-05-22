/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.17
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { CommonAuditdetail } from './common-auditdetail';

/**
 * Gives informations about the user that created the object and the last user to have modified it.  If the object was never modified after creation, objAuditdetailModified won\'t be returned. 
 * @export
 * @interface CommonAudit
 */
export interface CommonAudit {
    /**
     * 
     * @type {CommonAuditdetail}
     * @memberof CommonAudit
     */
    'objAuditdetailCreated': CommonAuditdetail;
    /**
     * 
     * @type {CommonAuditdetail}
     * @memberof CommonAudit
     */
    'objAuditdetailModified'?: CommonAuditdetail;
}
/**
 * @import
 * Imports Child Data Object
 */
// @ts-ignore
import { DataObjectCommonAuditdetail } from './'
// @ts-ignore
import { DataObjectCommonAuditdetail } from './'
// @ts-ignore
import { ValidationObjectCommonAuditdetail } from './'
// @ts-ignore
import { ValidationObjectCommonAuditdetail } from './'

/**
 * @export 
 * A CommonAudit Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectCommonAudit
 */
export class DataObjectCommonAudit {
   objAuditdetailCreated:CommonAuditdetail = new DataObjectCommonAuditdetail()
   objAuditdetailModified?:CommonAuditdetail = undefined
}

/**
 * @export 
 * A CommonAudit Validation Object
 * @class ValidationObjectCommonAudit
 */
export class ValidationObjectCommonAudit {
   objAuditdetailCreated = new ValidationObjectCommonAuditdetail()
   objAuditdetailModified = new ValidationObjectCommonAuditdetail()
} 


