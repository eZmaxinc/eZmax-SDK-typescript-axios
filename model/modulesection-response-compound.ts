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


// May contain unused imports in some cases
// @ts-ignore
import { ModulesectionResponse } from './modulesection-response';
// May contain unused imports in some cases
// @ts-ignore
import { ModulesectionResponseCompoundAllOf } from './modulesection-response-compound-all-of';
// May contain unused imports in some cases
// @ts-ignore
import { PermissionResponseCompound } from './permission-response-compound';

/**
 * @type ModulesectionResponseCompound
 * A Modulesection Object
 * @export
 */
export type ModulesectionResponseCompound = ModulesectionResponse & ModulesectionResponseCompoundAllOf;


/**
 * @import
 * Imports Child Data Object
 */

/**
 * @export 
 * A ModulesectionResponseCompound Data Object with automatic temporary default value
 * Use this object only for create an empty data object to assign a response from server
 * @class DataObjectModulesectionResponseCompound
 */
export class DataObjectModulesectionResponseCompound {
    pkiModulesectionID:number = 0
    fkiModuleID:number = 0
    sModulesectionInternalname:string = ''
    sModulesectionNameX:string = ''
    a_objPermission:Array<PermissionResponseCompound> = []
}

/**
 * @export 
 * A ModulesectionResponseCompound Validation Object
 * @class ValidationObjectModulesectionResponseCompound
 */
export class ValidationObjectModulesectionResponseCompound {
   pkiModulesectionID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   fkiModuleID = {
      type: 'integer',
      minimum: 0,
      required: true
   }
   sModulesectionInternalname = {
      type: 'string',
      required: true
   }
   sModulesectionNameX = {
      type: 'string',
      required: true
   }
   a_objPermission = {
      type: 'array',
      required: true
   }
} 


