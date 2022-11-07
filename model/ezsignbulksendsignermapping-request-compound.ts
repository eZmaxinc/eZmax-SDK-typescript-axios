/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.15
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsignbulksendsignermappingRequest } from './ezsignbulksendsignermapping-request';

import { DefaultObject } from '../base'

/**
 * @type EzsignbulksendsignermappingRequestCompound
 * A Ezsignbulksendsignermapping Object and children
 * @export
 */
export type EzsignbulksendsignermappingRequestCompound = EzsignbulksendsignermappingRequest;


/**
 * @export 
 * A EzsignbulksendsignermappingRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsignbulksendsignermappingRequestCompound
 */
export class DefaultObjectEzsignbulksendsignermappingRequestCompound extends DefaultObject {
   pkiEzsignbulksendsignermappingID?:number = undefined
   fkiEzsignbulksendID:number = 0
   fkiUserID?:number = undefined
   sEzsignbulksendsignermappingDescription:string = ''
}


