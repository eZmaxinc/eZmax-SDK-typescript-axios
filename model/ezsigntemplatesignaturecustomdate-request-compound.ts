/* tslint:disable */
/* eslint-disable */
/**
 * eZmax API Definition (Full)
 * This API expose all the functionnalities for the eZmax and eZsign applications.
 *
 * The version of the OpenAPI document: 1.1.13
 * Contact: support-api@ezmax.ca
 *
 * NOTE: This class is auto generated by OpenAPI Generator (https://openapi-generator.tech).
 * https://openapi-generator.tech
 * Do not edit the class manually.
 */


// May contain unused imports in some cases
// @ts-ignore
import { EzsigntemplatesignaturecustomdateRequest } from './ezsigntemplatesignaturecustomdate-request';

import { DefaultObject } from '../base'

/**
 * @type EzsigntemplatesignaturecustomdateRequestCompound
 * An Ezsigntemplatesignaturecustomdate Object and children to create a complete structure
 * @export
 */
export type EzsigntemplatesignaturecustomdateRequestCompound = EzsigntemplatesignaturecustomdateRequest;


/**
 * @export 
 * A EzsigntemplatesignaturecustomdateRequestCompound Object with automatic temp default value
 * Use this object only for create an empty object to assign a response from server
 * @class DefaultObjectEzsigntemplatesignaturecustomdateRequestCompound
 */
export class DefaultObjectEzsigntemplatesignaturecustomdateRequestCompound extends DefaultObject {
   pkiEzsigntemplatesignaturecustomdateID?:number = undefined
   iEzsigntemplatesignaturecustomdateX:number = 0
   iEzsigntemplatesignaturecustomdateY:number = 0
   sEzsigntemplatesignaturecustomdateFormat:string = ''
}


